use std::sync::{Arc, atomic::AtomicU32};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use wormhole_proto::{
    codec::{read_response_head, write_stream_header},
    frames::{HeaderField, HttpRequestHead, StreamHeader},
};

use super::{BoxError, accept_mux_streams, build_request, dispatch_stream, handle_buffered_result};
use crate::{
    driver::DriverEvent,
    model::{ResolvedTarget, RetryPolicy},
    wormhole_conn::{ConnCommand, EndpointHandle},
};

fn body() -> super::ClientBody {
    Full::new(Bytes::new()).map_err(|never| -> BoxError { match never {} }).boxed_unsync()
}

#[test]
fn local_request_strips_connection_nominated_headers() {
    let head = HttpRequestHead {
        method: "GET".to_owned(),
        uri: "/path".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![
            field("host", "demo.example"),
            field("connection", "keep-alive, x-private"),
            field("x-private", "secret"),
            field("keep-alive", "timeout=5"),
        ],
    };

    let request = build_request(head, body(), false).expect("request");

    assert_eq!(request.uri(), "/path");
    assert_eq!(request.headers().get("host").expect("host"), "demo.example");
    assert!(!request.headers().contains_key("connection"));
    assert!(!request.headers().contains_key("x-private"));
}

#[test]
fn local_upgrade_request_preserves_required_upgrade_headers() {
    let head = HttpRequestHead {
        method: "GET".to_owned(),
        uri: "/socket".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![field("connection", "upgrade"), field("upgrade", "websocket")],
    };

    let request = build_request(head, body(), true).expect("upgrade request");

    assert_eq!(request.headers().get("connection").expect("connection"), "upgrade");
    assert_eq!(request.headers().get("upgrade").expect("upgrade"), "websocket");
}

#[tokio::test]
async fn dispatches_http_request_and_response_over_stream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = vec![0_u8; 4096];
        let length = stream.read(&mut request).await.expect("request");
        let request = &request[..length];
        assert!(request.windows(8).any(|part| part == b"/deliver"));
        assert!(request.ends_with(b"payload"));
        stream
            .write_all(
                b"HTTP/1.1 201 Created\r\ncontent-length: 7\r\nconnection: close\r\n\r\ncreated",
            )
            .await
            .expect("response");
    });
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("POST", "/deliver", 7),
        endpoint(target, None, true),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.write_all(b"payload").await.expect("body");
    request.shutdown().await.expect("request eof");
    let head = read_response_head(&mut response).await.expect("response head");
    assert_eq!(head.status, 201);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"created");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn preserves_upgraded_http_stream_bidirectionally() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = vec![0_u8; 4096];
        let length = stream.read(&mut request).await.expect("request");
        assert!(request[..length].windows(9).any(|part| part == b"websocket"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n",
            )
            .await
            .expect("upgrade");
        let mut input = [0_u8; 4];
        stream.read_exact(&mut input).await.expect("upgraded input");
        assert_eq!(&input, b"ping");
        stream.write_all(b"pong").await.expect("upgraded output");
    });
    let mut header = http_header("GET", "/socket", 0);
    if let StreamHeader::Http { request, .. } = &mut header {
        request.headers = vec![field("connection", "upgrade"), field("upgrade", "websocket")];
    }
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        header,
        endpoint(target, None, false),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    let head = read_response_head(&mut response).await.expect("response head");
    assert_eq!(head.status, 101);
    request.write_all(b"ping").await.expect("upgraded write");
    let mut output = [0_u8; 4];
    response.read_exact(&mut output).await.expect("upgraded read");
    assert_eq!(&output, b"pong");
    request.shutdown().await.expect("shutdown");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn retries_replayable_request_after_server_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        for (status, body) in [(503, "retry"), (200, "done!")] {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let length = stream.read(&mut request).await.expect("request");
            assert!(request[..length].ends_with(b"payload"));
            let response = format!(
                "HTTP/1.1 {status} Test\r\ncontent-length: 5\r\nconnection: close\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await.expect("response");
        }
    });
    let retry = RetryPolicy {
        max_attempts: 2,
        initial_delay_ms: 0,
        max_delay_ms: 0,
        retry_connect: true,
        retry_5xx: true,
        max_body_bytes: 1024,
        total_deadline_ms: 5_000,
    };
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("POST", "/retry", 7),
        endpoint(target, Some(retry), true),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.write_all(b"payload").await.expect("body");
    request.shutdown().await.expect("request eof");
    let head = read_response_head(&mut response).await.expect("response head");
    assert_eq!(head.status, 200);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"done!");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn live_response_body_cannot_outlive_retry_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = vec![0_u8; 4096];
        let _read = stream.read(&mut request).await.expect("request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\n")
            .await
            .expect("response head");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });
    let retry = RetryPolicy {
        max_attempts: 1,
        initial_delay_ms: 0,
        max_delay_ms: 0,
        retry_connect: true,
        retry_5xx: true,
        max_body_bytes: 1024,
        total_deadline_ms: 100,
    };
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let started = tokio::time::Instant::now();
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("GET", "/slow", 0),
        endpoint(target, Some(retry), false),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.shutdown().await.expect("request eof");
    assert_eq!(read_response_head(&mut response).await.expect("response head").status, 200);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response closes");
    dispatch.await.expect("dispatch task");
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    local.abort();
}

#[tokio::test]
async fn forwards_spooled_error_when_retry_attempts_are_exhausted() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = vec![0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("request");
        stream
            .write_all(b"HTTP/1.1 503 Retry\r\ncontent-length: 5\r\nconnection: close\r\n\r\nretry")
            .await
            .expect("response");
    });
    let retry = RetryPolicy {
        max_attempts: 1,
        initial_delay_ms: 0,
        max_delay_ms: 0,
        retry_connect: true,
        retry_5xx: true,
        max_body_bytes: 1024,
        total_deadline_ms: 5_000,
    };
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("GET", "/failure", 0),
        endpoint(target, Some(retry), true),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.shutdown().await.expect("request eof");
    let head = read_response_head(&mut response).await.expect("response head");
    assert_eq!(head.status, 503);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"retry");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn retries_when_local_listener_appears_after_initial_connect_failure() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve listener");
    let target = reservation.local_addr().expect("target");
    drop(reservation);
    let retry = RetryPolicy {
        max_attempts: 3,
        initial_delay_ms: 100,
        max_delay_ms: 100,
        retry_connect: true,
        retry_5xx: false,
        max_body_bytes: 1024,
        total_deadline_ms: 5_000,
    };
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("POST", "/retry-connect", 7),
        endpoint(target, Some(retry), false),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.write_all(b"payload").await.expect("body");
    request.shutdown().await.expect("request eof");
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let listener = tokio::net::TcpListener::bind(target).await.expect("late listener");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("retry accept");
        let mut request = Vec::new();
        while !request.ends_with(b"payload") {
            let mut chunk = [0_u8; 256];
            let length = stream.read(&mut chunk).await.expect("retry request");
            assert_ne!(length, 0, "retry request body ended early");
            request.extend_from_slice(&chunk[..length]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("response");
    });
    assert_eq!(read_response_head(&mut response).await.expect("response head").status, 200);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"ok");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn oversized_request_streams_once_without_unsafe_retry() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        while !request.ends_with(b"payload-too-large") {
            let mut chunk = [0_u8; 256];
            let length = stream.read(&mut chunk).await.expect("request");
            assert_ne!(length, 0, "request body ended early");
            request.extend_from_slice(&chunk[..length]);
        }
        stream
            .write_all(b"HTTP/1.1 503 Retry\r\ncontent-length: 5\r\nconnection: close\r\n\r\nonce!")
            .await
            .expect("response");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let retry = RetryPolicy {
        max_attempts: 3,
        initial_delay_ms: 0,
        max_delay_ms: 0,
        retry_connect: true,
        retry_5xx: true,
        max_body_bytes: 4,
        total_deadline_ms: 5_000,
    };
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("POST", "/stream-once", 17),
        endpoint(target, Some(retry), false),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.write_all(b"payload-too-large").await.expect("body");
    request.shutdown().await.expect("request eof");
    assert_eq!(read_response_head(&mut response).await.expect("response head").status, 503);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"once!");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn dispatches_raw_tcp_bidirectionally() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut input = [0_u8; 4];
        stream.read_exact(&mut input).await.expect("input");
        assert_eq!(&input, b"ping");
        stream.write_all(b"pong").await.expect("output");
    });
    let (mut client, relay) = tokio::io::duplex(1024);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        StreamHeader::Tcp {
            bind: uuid::Uuid::nil(),
            peer: "127.0.0.1:1234".parse().expect("peer"),
        },
        endpoint(target, None, true),
    ));
    client.write_all(b"ping").await.expect("write");
    let mut output = [0_u8; 4];
    client.read_exact(&mut output).await.expect("read");
    assert_eq!(&output, b"pong");
    client.shutdown().await.expect("shutdown");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

#[tokio::test]
async fn mux_acceptor_rejects_bad_and_unknown_headers_then_dispatches_known_bind() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let bind = uuid::Uuid::now_v7();
    let binds = Arc::new(DashMap::new());
    binds.insert(bind, endpoint(target, None, false));
    let (incoming, streams) = tokio::sync::mpsc::channel(4);
    let acceptor = tokio::spawn(accept_mux_streams(streams, Arc::clone(&binds)));

    let (mut malformed, relay) = tokio::io::duplex(64);
    incoming.send(relay).await.expect("malformed stream");
    malformed.write_all(&[0xff]).await.expect("invalid header");
    malformed.shutdown().await.expect("malformed eof");
    let mut closed = Vec::new();
    malformed.read_to_end(&mut closed).await.expect("malformed close");

    let (mut unknown, relay) = tokio::io::duplex(1024);
    incoming.send(relay).await.expect("unknown stream");
    write_stream_header(&mut unknown, &http_header_for(uuid::Uuid::now_v7(), "GET", "/", 0))
        .await
        .expect("unknown header");
    unknown.shutdown().await.expect("unknown eof");
    closed.clear();
    unknown.read_to_end(&mut closed).await.expect("unknown close");

    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0_u8; 1024];
        let length = stream.read(&mut request).await.expect("request");
        assert!(request[..length].windows(4).any(|part| part == b"/mux"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await
            .expect("response");
    });
    let (mut known, relay) = tokio::io::duplex(4096);
    incoming.send(relay).await.expect("known stream");
    write_stream_header(&mut known, &http_header_for(bind, "GET", "/mux", 0))
        .await
        .expect("known header");
    known.shutdown().await.expect("known eof");
    assert_eq!(read_response_head(&mut known).await.expect("response").status, 204);
    known.read_to_end(&mut closed).await.expect("response eof");

    drop(incoming);
    acceptor.await.expect("acceptor");
    local.await.expect("local server");
}

#[tokio::test]
async fn saturated_endpoint_rejects_stream_without_local_delivery() {
    let (mut client, relay) = tokio::io::duplex(128);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let handle = endpoint("127.0.0.1:1".parse().expect("target"), None, false);
    handle.semaphore.close();
    dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("GET", "/busy", 0),
        handle,
    )
    .await;
    let mut closed = Vec::new();
    client.read_to_end(&mut closed).await.expect("closed stream");
    assert!(closed.is_empty());
}

#[tokio::test]
async fn buffered_delivery_reports_success_and_local_connect_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0_u8; 1024];
        let _read = stream.read(&mut request).await.expect("request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("response");
    });
    let (handle, _events, mut commands) = endpoint_channels(target, None, false);
    let (client, relay) = tokio::io::duplex(4096);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let mut header = http_header("GET", "/buffered", 0);
    if let StreamHeader::Http { buffered, .. } = &mut header {
        *buffered = Some(7);
    }
    let dispatch =
        tokio::spawn(dispatch_stream(Box::new(relay_write), Box::new(relay_read), header, handle));
    let (mut response, mut request) = tokio::io::split(client);
    request.shutdown().await.expect("request eof");
    assert_eq!(read_response_head(&mut response).await.expect("response").status, 200);
    response.read_to_end(&mut Vec::new()).await.expect("response eof");
    dispatch.await.expect("dispatch");
    assert!(matches!(
        commands.recv().await,
        Some(ConnCommand::BufferedResult { seq: 7, result: Ok(()), .. })
    ));
    local.await.expect("local server");

    let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve target");
    let missing = reservation.local_addr().expect("missing target");
    drop(reservation);
    let (handle, mut events, mut commands) = endpoint_channels(missing, None, false);
    let (mut client, relay) = tokio::io::duplex(4096);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let mut header = http_header("GET", "/buffered-failure", 0);
    if let StreamHeader::Http { buffered, .. } = &mut header {
        *buffered = Some(8);
    }
    dispatch_stream(Box::new(relay_write), Box::new(relay_read), header, handle).await;
    client.read_to_end(&mut Vec::new()).await.expect("failed stream close");
    assert!(matches!(
        commands.recv().await,
        Some(ConnCommand::BufferedResult { seq: 8, result: Err(_), .. })
    ));
    assert!(matches!(
        events.recv().await,
        Some(DriverEvent::Log(_, message)) if message.contains("delivery exhausted")
    ));
}

#[tokio::test]
async fn buffered_transport_interruption_logs_without_acknowledging_delivery() {
    let (handle, mut events, mut commands) =
        endpoint_channels("127.0.0.1:1".parse().expect("target"), None, false);
    handle_buffered_result(
        &handle,
        uuid::Uuid::nil(),
        9,
        Err(crate::error::DriverError::Cancelled),
    )
    .await;
    assert!(matches!(
        events.recv().await,
        Some(DriverEvent::Log(_, message)) if message.contains("transport interrupted")
    ));
    assert!(commands.try_recv().is_err());
}

#[tokio::test]
async fn retry_failures_return_gateway_timeout_for_connect_and_truncated_response() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve target");
    let missing = reservation.local_addr().expect("missing target");
    drop(reservation);
    assert_gateway_timeout(
        missing,
        RetryPolicy {
            max_attempts: 1,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            retry_connect: false,
            retry_5xx: true,
            max_body_bytes: 1024,
            total_deadline_ms: 5_000,
        },
    )
    .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0_u8; 1024];
        let _read = stream.read(&mut request).await.expect("request");
        stream
            .write_all(b"HTTP/1.1 503 Retry\r\ncontent-length: 5\r\nconnection: close\r\n\r\nno")
            .await
            .expect("truncated response");
    });
    assert_gateway_timeout(
        target,
        RetryPolicy {
            max_attempts: 1,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            retry_connect: true,
            retry_5xx: true,
            max_body_bytes: 1024,
            total_deadline_ms: 5_000,
        },
    )
    .await;
    local.await.expect("local server");

    assert_gateway_timeout(
        missing,
        RetryPolicy {
            max_attempts: 2,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            retry_connect: true,
            retry_5xx: false,
            max_body_bytes: 1024,
            total_deadline_ms: 0,
        },
    )
    .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let target = listener.local_addr().expect("target");
    let local = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0_u8; 1024];
        let _read = stream.read(&mut request).await.expect("request");
        stream
            .write_all(b"HTTP/1.1 503 Retry\r\ncontent-length: 5\r\nconnection: close\r\n\r\nretry")
            .await
            .expect("retry response");
    });
    assert_gateway_timeout(
        target,
        RetryPolicy {
            max_attempts: 2,
            initial_delay_ms: 2_000,
            max_delay_ms: 2_000,
            retry_connect: true,
            retry_5xx: true,
            max_body_bytes: 1024,
            total_deadline_ms: 1_000,
        },
    )
    .await;
    local.await.expect("local server");
}

async fn assert_gateway_timeout(target: std::net::SocketAddr, retry: RetryPolicy) {
    let (client, relay) = tokio::io::duplex(4096);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let dispatch = tokio::spawn(dispatch_stream(
        Box::new(relay_write),
        Box::new(relay_read),
        http_header("GET", "/retry-failure", 0),
        endpoint(target, Some(retry), false),
    ));
    let (mut response, mut request) = tokio::io::split(client);
    request.shutdown().await.expect("request eof");
    assert_eq!(read_response_head(&mut response).await.expect("response").status, 504);
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.expect("response body");
    assert_eq!(body, b"Gateway Timeout");
    dispatch.await.expect("dispatch");
}

fn http_header(method: &str, uri: &str, content_length: usize) -> StreamHeader {
    http_header_for(uuid::Uuid::nil(), method, uri, content_length)
}

fn http_header_for(
    bind: uuid::Uuid,
    method: &str,
    uri: &str,
    content_length: usize,
) -> StreamHeader {
    StreamHeader::Http {
        bind,
        peer: "127.0.0.1:1234".parse().expect("peer"),
        request: HttpRequestHead {
            method: method.to_owned(),
            uri: uri.to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![field("content-length", &content_length.to_string())],
        },
        buffered: None,
    }
}

fn endpoint(
    target: std::net::SocketAddr,
    retry: Option<RetryPolicy>,
    inspect: bool,
) -> Arc<EndpointHandle> {
    endpoint_channels(target, retry, inspect).0
}

fn endpoint_channels(
    target: std::net::SocketAddr,
    retry: Option<RetryPolicy>,
    inspect: bool,
) -> (
    Arc<EndpointHandle>,
    tokio::sync::mpsc::Receiver<DriverEvent>,
    tokio::sync::mpsc::Receiver<ConnCommand>,
) {
    let (events, event_rx) = tokio::sync::mpsc::channel::<DriverEvent>(8);
    let (_forget_tx, forget) = tokio::sync::watch::channel(false);
    let (commands, command_rx) = tokio::sync::mpsc::channel::<ConnCommand>(8);
    let handle = Arc::new(EndpointHandle {
        target: ResolvedTarget(target),
        semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        stop: CancellationToken::new(),
        forget,
        events,
        inspect,
        inspect_assets: true,
        capture_body_max: 1024,
        retry,
        buffered_pending: AtomicU32::new(0),
        buffered_failed: AtomicU32::new(0),
        commands,
    });
    (handle, event_rx, command_rx)
}

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) }
}
