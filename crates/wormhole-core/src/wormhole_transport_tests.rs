use std::{sync::Arc, time::Duration};

use camino::Utf8PathBuf;
use futures::{SinkExt as _, StreamExt as _};
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use wormhole_proto::{
    HandshakeStep, Identity, KeyDecision, ServerHandshake,
    codec::ControlChannel,
    frames::{ControlFrame, Limits},
};

use super::{
    QUIC_IDLE_TIMEOUT, QUIC_KEEP_ALIVE, authenticate_io, client_endpoint, connect_remote_addresses,
    connect_remote_ws_addresses, root_store, websocket_tls,
};
use crate::{
    error::DriverError,
    remotes::{Remote, Transport},
    wormhole_connect::probe_remote,
};

fn remote() -> Remote {
    Remote::new("127.0.0.1:443".to_owned(), "relay.example.com".to_owned(), None)
}

#[test]
fn quic_client_detects_dead_relays_promptly() {
    assert_eq!(QUIC_KEEP_ALIVE, Duration::from_secs(3));
    assert_eq!(QUIC_IDLE_TIMEOUT, Duration::from_secs(10));
}

#[tokio::test]
async fn tls_configs_use_platform_roots_for_both_transports() {
    let remote = remote();
    let roots = root_store(&remote).expect("roots");
    assert!(!roots.is_empty());
    let websocket = websocket_tls(&remote).expect("websocket tls");
    assert_eq!(websocket.alpn_protocols, [b"http/1.1".to_vec()]);
    let endpoint = client_endpoint("127.0.0.1".parse().expect("ip"), &remote).expect("endpoint");
    drop(endpoint);
    let endpoint = client_endpoint("::1".parse().expect("ip"), &remote).expect("endpoint");
    drop(endpoint);
}

#[test]
fn custom_ca_must_exist_and_contain_certificates() {
    let directory = tempfile::tempdir().expect("tempdir");
    let missing = directory.path().join("missing.pem");
    let mut remote = remote();
    remote.trusted_ca = Some(Utf8PathBuf::from_path_buf(missing).expect("utf8"));
    assert!(matches!(root_store(&remote), Err(DriverError::Transport(_))));

    let empty = directory.path().join("empty.pem");
    std::fs::write(&empty, "not a certificate\n").expect("write");
    remote.trusted_ca = Some(Utf8PathBuf::from_path_buf(empty).expect("utf8"));
    assert!(matches!(root_store(&remote), Err(DriverError::Transport(_))));
}

#[tokio::test]
async fn quic_connect_and_probe_use_configured_ca_and_handshake() {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let identity = Identity::generate();
    let expected_key = identity.public_base64();
    let probe_key = expected_key.clone();
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let chain = vec![certificate.cert.der().clone()];
    let key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()));
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("TLS");
    tls.alpn_protocols = vec![wormhole_proto::ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS");
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().expect("address"),
    )
    .expect("server");
    let address = endpoint.local_addr().expect("address");
    let task_endpoint = endpoint.clone();
    let server = tokio::spawn(async move {
        let incoming = task_endpoint.accept().await.expect("incoming");
        let connection = incoming.await.expect("connection");
        let (send, recv) = connection.accept_bi().await.expect("control");
        serve_handshake(tokio::io::join(recv, send), expected_key, None).await;
        let incoming = task_endpoint.accept().await.expect("probe incoming");
        let connection = incoming.await.expect("probe");
        let (send, recv) = connection.accept_bi().await.expect("probe control");
        serve_handshake(tokio::io::join(recv, send), probe_key, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });
    let directory = tempfile::tempdir().expect("tempdir");
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, certificate.cert.pem()).expect("CA");
    let mut remote = Remote::new(address.to_string(), "localhost".to_owned(), None);
    remote.trusted_ca = Some(Utf8PathBuf::from_path_buf(ca).expect("utf8"));
    let addresses = vec!["127.0.0.1:0".parse().expect("unreachable"), address];
    let (client_endpoint, connection, _channel, welcome) =
        connect_remote_addresses(&remote, &identity, addresses, None).await.expect("connect");
    assert_eq!(welcome.limits.max_streams, 23);
    connection.close(0_u32.into(), b"done");
    client_endpoint.wait_idle().await;
    probe_remote(&remote, &identity).await.expect("probe");
    server.await.expect("server");
}

#[tokio::test]
async fn websocket_connect_bridges_mux_control_channel() {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let identity = Identity::generate();
    let expected_key = identity.public_base64();
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let chain = vec![certificate.cert.der().clone()];
    let key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()));
    let tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("TLS");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(tcp).await.expect("TLS accept");
            let socket = tokio_tungstenite::accept_async(tls).await.expect("websocket");
            let (endpoint, network, mut outbound) = wormhole_proto::mux_runtime::MuxEndpoint::spawn(
                wormhole_proto::mux_runtime::MuxRole::Server,
            );
            let bridge = tokio::spawn(async move {
                let (mut sink, mut source) = socket.split();
                loop {
                    tokio::select! {
                        incoming = source.next() => match incoming {
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                                if network.send(data.to_vec()).await.is_err() { return; }
                            }
                            _ => return,
                        },
                        outgoing = outbound.recv() => {
                            let Some(outgoing) = outgoing else { return };
                            if sink.send(tokio_tungstenite::tungstenite::Message::Binary(outgoing.into())).await.is_err() { return; }
                        }
                    }
                }
            });
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                serve_handshake(
                    endpoint.control,
                    expected_key.clone(),
                    (attempt == 0).then_some("whi_ws_enrollment"),
                ),
            )
            .await
            .expect("server handshake timeout");
            bridge.await.expect("bridge");
        }
    });
    let directory = tempfile::tempdir().expect("tempdir");
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, certificate.cert.pem()).expect("CA");
    let mut remote = Remote::new(address.to_string(), "localhost".to_owned(), None);
    remote.https_addr = Some(address.to_string());
    remote.trusted_ca = Some(Utf8PathBuf::from_path_buf(ca).expect("utf8"));
    let addresses = vec!["127.0.0.1:9".parse().expect("unreachable"), address];
    let result =
        connect_remote_ws_addresses(&remote, &identity, addresses, Some("whi_ws_enrollment")).await;
    let (channel, welcome, incoming) = match result {
        Ok(connected) => connected,
        Err(error) => {
            let server_result = server.await;
            panic!("websocket connect failed: {error}; server: {server_result:?}");
        }
    };
    assert_eq!(welcome.limits.max_binds, 7);
    drop(channel);
    drop(incoming);
    remote.transport = Transport::Auto;
    assert_eq!(
        probe_remote(&remote, &identity).await.expect("automatic WebSocket fallback probe"),
        Transport::Ws
    );
    server.await.expect("server");
}

#[tokio::test]
async fn authenticates_over_transport_independent_control_io() {
    let identity = Identity::generate();
    let expected_key = identity.public_base64();
    let (client, server) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(async move {
        let mut channel = ControlChannel::new(server);
        let limits = Limits { max_binds: 7, max_streams: 23 };
        let mut handshake = ServerHandshake::new(
            "relay.example.com",
            limits,
            Some("ready".to_owned()),
            move |key, _invite| {
                if key == expected_key { KeyDecision::Authorized } else { KeyDecision::Unknown }
            },
        );
        for _ in 0..2 {
            let frame = channel.recv().await.expect("client frame");
            let step = handshake.step(&frame).expect("handshake");
            channel.send(&reply(step)).await.expect("server frame");
        }
    });

    let (_channel, welcome) =
        authenticate_io(Box::new(client), &identity, "relay.example.com", None)
            .await
            .expect("authenticated");
    assert_eq!(welcome.limits.max_binds, 7);
    assert_eq!(welcome.limits.max_streams, 23);
    server.await.expect("server");
}

#[tokio::test]
async fn transport_independent_handshake_presents_transient_invite() {
    let identity = Identity::generate();
    let expected_key = identity.public_base64();
    let (client, server) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(async move {
        let mut channel = ControlChannel::new(server);
        let mut handshake = ServerHandshake::new(
            "relay.example.com",
            Limits { max_binds: 1, max_streams: 1 },
            None,
            move |key, invite| {
                if key == expected_key && invite == Some("whi_enrollment") {
                    KeyDecision::Authorized
                } else {
                    KeyDecision::Unknown
                }
            },
        );
        for _ in 0..2 {
            let frame = channel.recv().await.expect("client frame");
            channel
                .send(&reply(handshake.step(&frame).expect("handshake")))
                .await
                .expect("server frame");
        }
    });
    authenticate_io(Box::new(client), &identity, "relay.example.com", Some("whi_enrollment"))
        .await
        .expect("invited authentication");
    server.await.expect("server");
}

#[tokio::test]
async fn reports_relay_denial_without_retryable_transport_error() {
    let identity = Identity::generate();
    let (client, server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut channel = ControlChannel::new(server);
        let mut handshake = ServerHandshake::new(
            "relay.example.com",
            Limits { max_binds: 1, max_streams: 1 },
            None,
            |_, _| KeyDecision::Unknown,
        );
        for _ in 0..2 {
            let frame = channel.recv().await.expect("client frame");
            let step = handshake.step(&frame).expect("handshake");
            channel.send(&reply(step)).await.expect("server frame");
        }
    });
    let result = authenticate_io(Box::new(client), &identity, "relay.example.com", None).await;
    assert!(matches!(result, Err(DriverError::Denied(_))));
    server.await.expect("server");
}

async fn serve_handshake<T>(io: T, expected_key: String, expected_invite: Option<&str>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut channel = ControlChannel::new(io);
    let mut handshake = ServerHandshake::new(
        "localhost",
        Limits { max_binds: 7, max_streams: 23 },
        None,
        move |key, invite| {
            if key == expected_key && invite == expected_invite {
                KeyDecision::Authorized
            } else {
                KeyDecision::Unknown
            }
        },
    );
    for _ in 0..2 {
        let frame = channel.recv().await.expect("client frame");
        channel.send(&reply(handshake.step(&frame).expect("handshake"))).await.expect("reply");
    }
}

fn reply(step: HandshakeStep) -> ControlFrame {
    match step {
        HandshakeStep::Reply(frame)
        | HandshakeStep::Done { reply: Some(frame), .. }
        | HandshakeStep::Failed { reply: Some(frame), .. } => frame,
        other => panic!("expected reply, got {other:?}"),
    }
}
