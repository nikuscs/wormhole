use std::{net::SocketAddr, sync::Arc};

use camino::Utf8Path;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, join};
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use wormhole_proto::{
    ALPN, ClientHandshake, HandshakeStep, Identity,
    codec::{ControlChannel, read_stream_header, write_response_head},
    frames::{BindSpec, ControlFrame, DenyReason, HttpResponseHead, Persistence, StreamHeader},
};
use wormholed::{
    authz::{AuthStore, KeyLimits},
    certs::CertManager,
    config::{
        AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
        WormholedConfig,
    },
    db::RelayDb,
    edge_https::HttpsEdge,
    edge_tcp::TcpEdgeManager,
    quic::QuicServer,
    registry::{BindState, HostKey, Registry},
    state::AppState,
};

fn config(data_dir: camino::Utf8PathBuf) -> WormholedConfig {
    WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: Some(8443),
            quic_addr: "127.0.0.1:0".parse().expect("valid address"),
            https_addr: "127.0.0.1:0".parse().expect("valid address"),
            http_addr: "127.0.0.1:0".parse().expect("valid address"),
            data_dir: data_dir.clone(),
        },
        tls: TlsConfig { mode: TlsMode::SelfSigned, static_config: None, acme: None },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data_dir.join("keys") },
    }
}

fn client_endpoint(certificate: rustls::pki_types::CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).expect("test certificate must trust");
    let mut tls = RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("QUIC client config must build");
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("valid address"))
        .expect("client endpoint must bind");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

async fn connect(
    endpoint: &quinn::Endpoint,
    server: SocketAddr,
) -> (quinn::Connection, ControlChannel<tokio::io::Join<quinn::RecvStream, quinn::SendStream>>) {
    let connection = endpoint
        .connect(server, "tun.example.com")
        .expect("connection must start")
        .await
        .expect("connection must establish");
    let (send, recv) = connection.open_bi().await.expect("control stream must open");
    let channel = ControlChannel::new(join(recv, send));
    (connection, channel)
}

async fn authenticate(
    channel: &mut ControlChannel<tokio::io::Join<quinn::RecvStream, quinn::SendStream>>,
    handshake: &mut ClientHandshake<'_>,
) -> HandshakeStep {
    channel.send(&handshake.hello()).await.expect("hello must send");
    let challenge = channel.recv().await.expect("challenge must arrive");
    let HandshakeStep::Reply(auth) = handshake.step(&challenge).expect("challenge must verify")
    else {
        panic!("client must produce auth");
    };
    channel.send(&auth).await.expect("auth must send");
    let welcome = channel.recv().await.expect("welcome must arrive");
    handshake.step(&welcome).expect("welcome must complete")
}

async fn assert_wrong_key_denied(client: &quinn::Endpoint, server_addr: SocketAddr) {
    let identity = Identity::generate();
    let (connection, mut channel) = connect(client, server_addr).await;
    let mut handshake = ClientHandshake::new(&identity, "tun.example.com", "integration-test");
    assert!(matches!(
        authenticate(&mut channel, &mut handshake).await,
        HandshakeStep::Failed { reason: DenyReason::UnknownKey, .. }
    ));
    connection.close(0_u32.into(), b"done");
}

async fn bind_and_activate(
    client: &quinn::Endpoint,
    server_addr: SocketAddr,
    allowed: Identity,
    registry: &Registry,
    https_addr: SocketAddr,
    certificate: CertificateDer<'static>,
) -> quinn::Connection {
    let (connection, mut channel) = connect(client, server_addr).await;
    let mut handshake = ClientHandshake::new(&allowed, "tun.example.com", "integration-test");
    assert!(matches!(authenticate(&mut channel, &mut handshake).await, HandshakeStep::Done { .. }));
    let request = Uuid::now_v7();
    channel
        .send(&ControlFrame::Bind {
            request,
            spec: BindSpec::Http {
                host: Some("demo".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: None,
                auth: None,
            },
            reservation: None,
        })
        .await
        .expect("bind must send");
    let ControlFrame::Bound { bind, .. } = channel.recv().await.expect("bound must arrive") else {
        panic!("expected bound frame");
    };
    assert_route_state(registry, BindState::Pending);
    let pending = https_request(https_addr, certificate.clone()).await;
    assert!(pending.starts_with("HTTP/1.1 503"));
    channel.send(&ControlFrame::BindReady { bind }).await.expect("ready must send");
    assert_eq!(
        channel.recv().await.expect("active must arrive"),
        ControlFrame::BindActive { bind }
    );
    assert_route_state(registry, BindState::Online);
    let data_task = tokio::spawn(serve_one_tunneled_http(connection.clone()));
    let response = https_request(https_addr, certificate).await;
    data_task.await.expect("target task must finish");
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("target-response"));
    connection
}

fn assert_route_state(registry: &Registry, expected: BindState) {
    assert_eq!(
        registry
            .get(&HostKey::Hostname("demo.tun.example.com".to_owned()))
            .expect("route must exist")
            .state(),
        expected
    );
}

async fn https_request(address: SocketAddr, certificate: CertificateDer<'static>) -> String {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).expect("edge certificate must trust");
    let mut config =
        RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(address).await.expect("HTTPS edge must connect");
    let name = ServerName::try_from("demo.tun.example.com".to_owned()).expect("valid SNI");
    let mut tls = connector.connect(name, stream).await.expect("HTTPS TLS must connect");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: demo.tun.example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("HTTPS request must write");
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.expect("HTTPS response must read");
    String::from_utf8(response).expect("HTTP response must be UTF-8")
}

async fn serve_one_tunneled_http(connection: quinn::Connection) {
    let (mut send, mut recv) = connection.accept_bi().await.expect("data stream must arrive");
    let header = read_stream_header(&mut recv).await.expect("request head must read");
    assert!(matches!(header, StreamHeader::Http { .. }));
    recv.read_to_end(1024).await.expect("request body must finish");
    write_response_head(
        &mut send,
        &HttpResponseHead { status: 200, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
    )
    .await
    .expect("response head must write");
    send.write_all(b"target-response").await.expect("response body must write");
    send.finish().expect("response stream must finish");
}

#[tokio::test]
async fn wrong_and_right_keys_observe_pending_then_active_bind() {
    let directory = tempdir().expect("temporary directory");
    let data_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let config = config(data_dir.clone());
    let certificates = CertManager::ready(&config).await.expect("certificates must be ready");
    let server_certificate = certificates
        .resolver()
        .resolve_name("tun.example.com")
        .expect("default certificate must resolve")
        .cert[0]
        .clone();
    let database = Arc::new(RelayDb::open(&data_dir).expect("database must open"));
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&config.limits)));
    let allowed = Identity::generate();
    auth.authorize(&allowed.public_base64(), "allowed").expect("key must authorize");
    let registry = Arc::new(Registry::new(
        config.server.domains.clone(),
        config.server.public_https_port,
        config.server.https_addr.port(),
        config.tcp.port_range,
    ));
    let tcp_edges = Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("valid IP")));
    let state = Arc::new(
        AppState::new(
            Arc::clone(&registry),
            Arc::clone(&database),
            tcp_edges,
            auth,
            config.limits.clone(),
        )
        .expect("state must initialize"),
    );
    let server = Arc::new(
        QuicServer::bind(
            config.server.quic_addr,
            Arc::clone(&state),
            &certificates,
            "tun.example.com".to_owned(),
            30,
        )
        .expect("QUIC server must bind"),
    );
    let https = Arc::new(
        HttpsEdge::bind(
            "127.0.0.1:0".parse().expect("valid HTTPS address"),
            state,
            certificates.resolver(),
        )
        .await
        .expect("HTTPS edge must bind"),
    );
    let https_addr = https.local_addr().expect("HTTPS address");
    let https_task = tokio::spawn({
        let https = Arc::clone(&https);
        async move { https.run().await }
    });
    let server_addr = server.local_addr().expect("server address");
    let server_task = tokio::spawn({
        let server = Arc::clone(&server);
        async move { server.run().await }
    });
    let client = client_endpoint(server_certificate.clone());

    assert_wrong_key_denied(&client, server_addr).await;
    let connection =
        bind_and_activate(&client, server_addr, allowed, &registry, https_addr, server_certificate)
            .await;

    connection.close(0_u32.into(), b"done");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_route_state(&registry, BindState::Offline);
    client.close(0_u32.into(), b"done");
    server.endpoint().close(0_u32.into(), b"done");
    https_task.abort();
    server_task.await.expect("server task must stop");
}
