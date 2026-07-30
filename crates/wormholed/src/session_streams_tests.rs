use std::sync::Arc;

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
};
use uuid::Uuid;
use wormhole_proto::{
    codec::{read_stream_header, write_response_head},
    frames::{HeaderField, HttpRequestHead, HttpResponseHead, StreamHeader},
    mux_runtime::{MuxEndpoint, MuxRole},
};

use super::{
    DataOpener, OpenedHttp, body_response, copy_bidirectional_idle, copy_request_body,
    open_http_stream, response_while_sending, spawn_http_stream, spawn_tcp_stream, stream_bind,
    stream_response_body, timed_response_head,
};
use crate::{
    authz::{AuthStore, KeyLimits},
    config::{LimitsConfig, PortRange},
    db::RelayDb,
    edge_tcp::TcpEdgeManager,
    registry::{Registry, TunnelRead, TunnelWrite},
    state::AppState,
};

fn http_header(bind: Uuid) -> StreamHeader {
    StreamHeader::Http {
        bind,
        peer: "127.0.0.1:1234".parse().expect("peer"),
        request: HttpRequestHead {
            method: "POST".to_owned(),
            uri: "/hook".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
        },
        buffered: None,
    }
}

fn mux_pair() -> (DataOpener, mpsc::Receiver<tokio::io::DuplexStream>) {
    let (server, server_network, mut server_outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let (client, client_network, mut client_outbound) = MuxEndpoint::spawn(MuxRole::Client);
    let MuxEndpoint { control: server_control, incoming: _server_incoming, opener } = server;
    let MuxEndpoint { control: client_control, incoming, opener: _client_opener } = client;
    tokio::spawn(async move {
        let (_server_control, _client_control) = (server_control, client_control);
        std::future::pending::<()>().await;
    });
    tokio::spawn(async move {
        while let Some(frame) = server_outbound.recv().await {
            if client_network.send(frame).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = client_outbound.recv().await {
            if server_network.send(frame).await.is_err() {
                return;
            }
        }
    });
    (DataOpener::Mux(opener), incoming)
}

#[tokio::test]
async fn mux_http_body_round_trips_request_head_body_and_response() {
    let bind = Uuid::now_v7();
    let (opener, mut incoming) = mux_pair();
    let (body_tx, body_rx) = mpsc::channel(2);
    body_tx.send(Ok(Bytes::from_static(b"request"))).await.expect("body");
    drop(body_tx);
    let target = tokio::spawn(async move {
        let mut stream = incoming.recv().await.expect("incoming stream");
        assert_eq!(
            read_stream_header(&mut stream).await.expect("stream header"),
            http_header(bind)
        );
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.expect("request body");
        assert_eq!(request, b"request");
        write_response_head(
            &mut stream,
            &HttpResponseHead { status: 202, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response head");
        stream.write_all(b"response").await.expect("response body");
        stream.shutdown().await.expect("finish response");
    });

    let result =
        open_http_stream(opener, http_header(bind), body_rx, false).await.expect("open HTTP");
    let OpenedHttp::Body { response, sender, recv } = result else {
        panic!("expected body response");
    };
    assert_eq!(response.head.status, 202);
    let mut body = response.body;
    stream_response_body(recv, sender).await;
    assert_eq!(body.recv().await.expect("chunk").expect("body"), b"response"[..]);
    assert!(body.recv().await.is_none());
    target.await.expect("target");
}

#[tokio::test]
async fn upgrade_response_exposes_tunnel_until_release() {
    let bind = Uuid::now_v7();
    let (opener, mut incoming) = mux_pair();
    let (body_tx, body_rx) = mpsc::channel(1);
    drop(body_tx);
    let target = tokio::spawn(async move {
        let mut stream = incoming.recv().await.expect("incoming stream");
        assert_eq!(
            read_stream_header(&mut stream).await.expect("stream header"),
            http_header(bind)
        );
        write_response_head(
            &mut stream,
            &HttpResponseHead { status: 101, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response head");
        stream.write_all(b"upgraded").await.expect("upgrade bytes");
        let mut reply = [0_u8; 2];
        stream.read_exact(&mut reply).await.expect("upgrade reply");
        assert_eq!(&reply, b"ok");
    });

    let result =
        open_http_stream(opener, http_header(bind), body_rx, true).await.expect("open upgrade");
    let OpenedHttp::Upgrade { mut response, released } = result else {
        panic!("expected upgrade");
    };
    assert_eq!(response.head.status, 101);
    let mut tunnel = response.upgrade.take().expect("upgrade tunnel");
    let mut bytes = [0_u8; 8];
    tunnel.recv.read_exact(&mut bytes).await.expect("upgrade bytes");
    assert_eq!(&bytes, b"upgraded");
    tunnel.send.write_all(b"ok").await.expect("upgrade reply");
    let _ = tunnel.release.send(());
    released.await.expect("release observed");
    target.await.expect("target");
}

#[tokio::test]
async fn upgrade_request_with_regular_response_becomes_body_response() {
    let bind = Uuid::now_v7();
    let (opener, mut incoming) = mux_pair();
    let (body_tx, body_rx) = mpsc::channel(1);
    drop(body_tx);
    tokio::spawn(async move {
        let mut stream = incoming.recv().await.expect("incoming stream");
        assert_eq!(
            read_stream_header(&mut stream).await.expect("stream header"),
            http_header(bind)
        );
        write_response_head(
            &mut stream,
            &HttpResponseHead { status: 400, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response head");
        stream.shutdown().await.expect("finish response");
    });

    let result =
        open_http_stream(opener, http_header(bind), body_rx, true).await.expect("regular response");
    assert!(matches!(result, OpenedHttp::Body { response, .. } if response.head.status == 400));
}

#[tokio::test]
async fn request_and_response_body_failures_are_reported() {
    let (send, receive) = tokio::io::duplex(64);
    let mut send: TunnelWrite = Box::new(send);
    let (body_tx, mut body_rx) = mpsc::channel(1);
    body_tx.send(Err("source failed".to_owned())).await.expect("body error");
    assert_eq!(
        copy_request_body(&mut send, &mut body_rx).await.expect_err("copy fails"),
        "source failed"
    );
    drop(body_tx);
    drop(receive);

    let (read, write) = tokio::io::duplex(64);
    drop(write);
    let (sender, mut body) = mpsc::channel(1);
    stream_response_body(Box::new(read), sender).await;
    assert!(body.recv().await.is_none());

    let (read, write) = tokio::io::duplex(64);
    drop(write);
    let mut read: TunnelRead = Box::new(read);
    assert!(timed_response_head(&mut read).await.is_err());
}

#[tokio::test]
async fn bidirectional_copy_tracks_activity_in_both_directions() {
    let (mut left_app, left_tunnel) = tokio::io::duplex(128);
    let (right_tunnel, mut right_app) = tokio::io::duplex(128);
    let copy = tokio::spawn(copy_bidirectional_idle(left_tunnel, right_tunnel));

    left_app.write_all(b"left").await.expect("left write");
    let mut left = [0_u8; 4];
    right_app.read_exact(&mut left).await.expect("right read");
    assert_eq!(&left, b"left");
    right_app.write_all(b"right").await.expect("right write");
    let mut right = [0_u8; 5];
    left_app.read_exact(&mut right).await.expect("left read");
    assert_eq!(&right, b"right");
    left_app.shutdown().await.expect("left close");
    right_app.shutdown().await.expect("right close");
    assert_eq!(copy.await.expect("copy task").expect("copy"), (4, 5));
}

#[test]
fn stream_bind_and_body_response_preserve_metadata() {
    let bind = Uuid::now_v7();
    assert_eq!(stream_bind(&http_header(bind)), bind);
    let tcp = StreamHeader::Tcp { bind, peer: "127.0.0.1:42".parse().expect("peer") };
    assert_eq!(stream_bind(&tcp), bind);

    let (read, _write) = tokio::io::duplex(8);
    let opened = body_response(
        HttpResponseHead { status: 204, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        Box::new(read),
    );
    assert!(matches!(opened, OpenedHttp::Body { response, .. } if response.head.status == 204));
}

#[tokio::test]
async fn request_body_streams_all_chunks_and_propagates_source_failure() {
    let (writer, mut reader) = tokio::io::duplex(64);
    let mut writer: TunnelWrite = Box::new(writer);
    let (tx, mut rx) = mpsc::channel(3);
    tx.send(Ok(Bytes::from_static(b"hello "))).await.expect("first chunk");
    tx.send(Ok(Bytes::from_static(b"world"))).await.expect("second chunk");
    drop(tx);

    copy_request_body(&mut writer, &mut rx).await.expect("copy body");
    writer.shutdown().await.expect("shutdown");
    let mut body = Vec::new();
    reader.read_to_end(&mut body).await.expect("read body");
    assert_eq!(body, b"hello world");

    let (writer, _reader) = tokio::io::duplex(8);
    let mut writer: TunnelWrite = Box::new(writer);
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(Err("source failed".to_owned())).await.expect("error chunk");
    assert_eq!(copy_request_body(&mut writer, &mut rx).await.unwrap_err(), "source failed");
}

#[tokio::test]
async fn response_head_can_arrive_before_request_body_finishes() {
    let (mut target, relay) = tokio::io::duplex(512);
    let mut relay: TunnelRead = Box::new(relay);
    let (done, body_result) = tokio::sync::oneshot::channel();
    let expected = HttpResponseHead {
        status: 202,
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField { name: "x-result".to_owned(), value_b64: "b2s=".to_owned() }],
    };
    let sent = expected.clone();
    tokio::spawn(async move {
        write_response_head(&mut target, &sent).await.expect("response head");
        let _held = done;
        tokio::task::yield_now().await;
    });

    let actual = response_while_sending(&mut relay, body_result).await.expect("response head");
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn response_body_forwards_bytes_and_reports_reader_failure() {
    let (mut target, relay) = tokio::io::duplex(64);
    let relay: TunnelRead = Box::new(relay);
    let (tx, mut rx) = mpsc::channel(2);
    let task = tokio::spawn(stream_response_body(relay, tx));
    target.write_all(b"payload").await.expect("write payload");
    target.shutdown().await.expect("shutdown target");
    assert_eq!(rx.recv().await.expect("chunk").expect("body"), b"payload"[..]);
    assert!(rx.recv().await.is_none());
    task.await.expect("body task");
}

#[tokio::test]
async fn bidirectional_copy_bridges_both_directions() {
    let (left_public, mut left_peer) = tokio::io::duplex(64);
    let (right_tunnel, mut right_peer) = tokio::io::duplex(64);
    let task = tokio::spawn(copy_bidirectional_idle(left_public, right_tunnel));

    left_peer.write_all(b"request").await.expect("request");
    let mut request = [0_u8; 7];
    right_peer.read_exact(&mut request).await.expect("read request");
    assert_eq!(&request, b"request");
    right_peer.write_all(b"reply").await.expect("reply");
    let mut reply = [0_u8; 5];
    left_peer.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(&reply, b"reply");
    left_peer.shutdown().await.expect("left shutdown");
    right_peer.shutdown().await.expect("right shutdown");
    let copied = task.await.expect("copy task").expect("copy result");
    assert_eq!(copied, (7, 5));
}

fn stream_state() -> (tempfile::TempDir, Arc<AppState>) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = Arc::new(RelayDb::open(path).expect("database"));
    let limits = LimitsConfig::default();
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
    let registry = Arc::new(Registry::new(
        vec!["tun.example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    ));
    let state = Arc::new(
        AppState::new(
            registry,
            database,
            Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP"))),
            auth,
            limits,
        )
        .expect("state"),
    );
    (directory, state)
}

async fn wait_for_streams(state: &AppState, expected: u64) {
    for _ in 0..100 {
        if state.active_streams() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(state.active_streams(), expected);
}

#[tokio::test]
async fn spawned_stream_tasks_report_open_failures_and_release_tracking() {
    let (_directory, state) = stream_state();
    let slots = Arc::new(tokio::sync::Semaphore::new(3));
    let bind = Uuid::now_v7();
    let (opener, incoming) = mux_pair();
    drop(incoming);
    let (body_tx, body_rx) = mpsc::channel(1);
    drop(body_tx);
    let (reply, response) = tokio::sync::oneshot::channel();
    spawn_http_stream(
        opener,
        Arc::clone(&state),
        Arc::clone(&slots).acquire_owned().await.expect("permit"),
        http_header(bind),
        body_rx,
        false,
        reply,
    );
    assert!(response.await.expect("HTTP reply").is_err());
    wait_for_streams(&state, 0).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let connect = tokio::net::TcpStream::connect(listener.local_addr().expect("address"));
    let (public, _) = tokio::join!(connect, listener.accept());
    let (opener, incoming) = mux_pair();
    drop(incoming);
    spawn_tcp_stream(
        opener,
        Arc::clone(&state),
        Arc::clone(&slots).acquire_owned().await.expect("permit"),
        StreamHeader::Tcp { bind, peer: "127.0.0.1:42".parse().expect("peer") },
        public.expect("public stream"),
    );
    wait_for_streams(&state, 0).await;
}

#[tokio::test]
async fn spawned_upgrade_waits_for_release_and_dropped_reply_stops_body_stream() {
    let (_directory, state) = stream_state();
    let slots = Arc::new(tokio::sync::Semaphore::new(2));
    let bind = Uuid::now_v7();
    let (opener, mut incoming) = mux_pair();
    let target = tokio::spawn(async move {
        let mut stream = incoming.recv().await.expect("incoming upgrade");
        read_stream_header(&mut stream).await.expect("header");
        write_response_head(
            &mut stream,
            &HttpResponseHead { status: 101, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response");
    });
    let (body_tx, body_rx) = mpsc::channel(1);
    drop(body_tx);
    let (reply, response) = tokio::sync::oneshot::channel();
    spawn_http_stream(
        opener,
        Arc::clone(&state),
        Arc::clone(&slots).acquire_owned().await.expect("permit"),
        http_header(bind),
        body_rx,
        true,
        reply,
    );
    let mut response = response.await.expect("upgrade response").expect("upgrade");
    let tunnel = response.upgrade.take().expect("tunnel");
    tunnel.release.send(()).expect("release");
    target.await.expect("upgrade target");
    wait_for_streams(&state, 0).await;

    let (opener, mut incoming) = mux_pair();
    let target = tokio::spawn(async move {
        let mut stream = incoming.recv().await.expect("incoming body");
        read_stream_header(&mut stream).await.expect("header");
        write_response_head(
            &mut stream,
            &HttpResponseHead { status: 204, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response");
    });
    let (body_tx, body_rx) = mpsc::channel(1);
    drop(body_tx);
    let (reply, response) = tokio::sync::oneshot::channel();
    drop(response);
    spawn_http_stream(
        opener,
        Arc::clone(&state),
        slots.acquire_owned().await.expect("permit"),
        http_header(bind),
        body_rx,
        false,
        reply,
    );
    target.await.expect("body target");
    wait_for_streams(&state, 0).await;
}
