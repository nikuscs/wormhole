use std::sync::{Arc, atomic::AtomicU32};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use wormhole_proto::{
    codec::read_response_head,
    frames::{HeaderField, HttpRequestHead, StreamHeader},
};

use super::{BoxError, build_request, dispatch_stream};
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
        endpoint(target, Some(retry), false),
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
        endpoint(target, None, false),
    ));
    client.write_all(b"ping").await.expect("write");
    let mut output = [0_u8; 4];
    client.read_exact(&mut output).await.expect("read");
    assert_eq!(&output, b"pong");
    client.shutdown().await.expect("shutdown");
    dispatch.await.expect("dispatch");
    local.await.expect("local server");
}

fn http_header(method: &str, uri: &str, content_length: usize) -> StreamHeader {
    StreamHeader::Http {
        bind: uuid::Uuid::nil(),
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
    let (events, _event_rx) = tokio::sync::mpsc::channel::<DriverEvent>(8);
    let (_forget_tx, forget) = tokio::sync::watch::channel(false);
    let (commands, _command_rx) = tokio::sync::mpsc::channel::<ConnCommand>(8);
    Arc::new(EndpointHandle {
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
    })
}

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) }
}
