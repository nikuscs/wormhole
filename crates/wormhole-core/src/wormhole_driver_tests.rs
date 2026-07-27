use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use camino::Utf8PathBuf;
use quinn::Endpoint;
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_proto::{
    ALPN, HandshakeStep, KeyDecision, ServerHandshake,
    codec::{ControlChannel, write_stream_header},
    frames::{BindSpec, BufferPolicy, ControlFrame, Limits, Persistence, StreamHeader},
};

use super::WormholeDriver;
use crate::{
    driver::{DriverEvent, TunnelDriver},
    keys_store::IdentityStore,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
    remotes::Remote,
};

#[test]
fn tcp_buffering_is_rejected_before_wire_translation() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let driver =
        WormholeDriver::new(BTreeMap::new(), None, Arc::new(IdentityStore::with_home(home)));
    let mut endpoint = spec(11_001);
    endpoint.buffer = Some(BufferPolicy { max_requests: 1, max_body_bytes: 1024, ttl_secs: 60 });
    assert!(driver.validate(&endpoint).is_err());
}

#[tokio::test]
async fn two_binds_share_connection_and_route_to_distinct_targets() {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let identities = Arc::new(IdentityStore::with_home(home));
    let identity_remote = remote("127.0.0.1:1", None);
    let identity = identities.resolve_identity(&identity_remote).expect("identity");
    let (mut server, certificate) = fake_server(identity.public_base64());
    let address = server.endpoint.local_addr().expect("server address");
    let ca_path = Utf8PathBuf::from_path_buf(directory.path().join("ca.pem")).expect("CA path");
    std::fs::write(&ca_path, certificate.cert.pem()).expect("CA PEM");
    let remote = remote(&address.to_string(), Some(ca_path));
    let driver = Arc::new(WormholeDriver::new(
        BTreeMap::from([("test".to_owned(), remote)]),
        Some("test".to_owned()),
        identities,
    ));
    let first = echo_target(b"first", 1).await;
    let second = echo_target(b"second", 2).await;
    let (events_one, _events_rx_one) = mpsc::channel::<DriverEvent>(16);
    let (events_two, _events_rx_two) = mpsc::channel::<DriverEvent>(16);
    let stop_one = CancellationToken::new();
    let stop_two = CancellationToken::new();
    let one = tokio::spawn(run_driver(
        Arc::clone(&driver),
        spec(11_001),
        ResolvedTarget(first),
        events_one,
        stop_one.clone(),
    ));
    let two = tokio::spawn(run_driver(
        driver,
        spec(11_002),
        ResolvedTarget(second),
        events_two,
        stop_two.clone(),
    ));

    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.push(
            tokio::time::timeout(Duration::from_secs(5), server.results.recv())
                .await
                .expect("stream timeout")
                .expect("stream result"),
        );
    }
    responses.sort_by_key(|(marker, _)| *marker);
    assert_eq!(responses, [(11_001, b"first".to_vec()), (11_002, b"second".to_vec())]);
    assert_eq!(server.connections.load(Ordering::Acquire), 1);

    stop_one.cancel();
    one.await.expect("first driver task").expect("first driver");
    let remaining = tokio::time::timeout(Duration::from_secs(5), server.results.recv())
        .await
        .expect("remaining stream timeout")
        .expect("remaining stream result");
    assert_eq!(remaining, (11_002, b"second".to_vec()));

    stop_two.cancel();
    two.await.expect("second driver task").expect("second driver");
    server.task.abort();
}

async fn run_driver(
    driver: Arc<WormholeDriver>,
    spec: EndpointSpec,
    target: ResolvedTarget,
    events: mpsc::Sender<DriverEvent>,
    stop: CancellationToken,
) -> Result<(), crate::error::DriverError> {
    driver.run(spec, target, events, stop).await
}

fn spec(marker: u16) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Tcp,
        driver: "wormhole".to_owned(),
        qualifier: None,
        remote: None,
        host: None,
        domain: None,
        public_port: Some(marker),
        persist: Persistence::Temporary,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 1024 * 1024,
        reservation: None,
    }
}

fn remote(addr: &str, trusted_ca: Option<Utf8PathBuf>) -> Remote {
    let mut value = toml::Table::new();
    value.insert("addr".to_owned(), toml::Value::String(addr.to_owned()));
    value.insert("server_name".to_owned(), toml::Value::String("localhost".to_owned()));
    if let Some(path) = trusted_ca {
        value.insert("trusted_ca".to_owned(), toml::Value::String(path.to_string()));
    }
    toml::Value::Table(value).try_into().expect("remote")
}

async fn echo_target(response: &'static [u8], accepts: usize) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("target");
    let address = listener.local_addr().expect("target address");
    tokio::spawn(async move {
        for _ in 0..accepts {
            let (mut stream, _) = listener.accept().await.expect("target accept");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.expect("target read");
            assert_eq!(request, b"request");
            stream.write_all(response).await.expect("target response");
        }
    });
    address
}

struct FakeServer {
    endpoint: Endpoint,
    results: mpsc::Receiver<(u16, Vec<u8>)>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

fn fake_server(public_key: String) -> (FakeServer, rcgen::CertifiedKey<rcgen::KeyPair>) {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let chain = vec![certificate.cert.der().clone()];
    let key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()));
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("TLS config");
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS");
    let endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().expect("address"),
    )
    .expect("server endpoint");
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    let endpoint_task = endpoint.clone();
    let (results_tx, results) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let incoming = endpoint_task.accept().await.expect("incoming");
        counter.fetch_add(1, Ordering::AcqRel);
        let connection = incoming.await.expect("connection");
        run_fake_connection(connection, &public_key, results_tx).await;
    });
    (FakeServer { endpoint, results, connections, task }, certificate)
}

async fn run_fake_connection(
    connection: quinn::Connection,
    public_key: &str,
    results: mpsc::Sender<(u16, Vec<u8>)>,
) {
    let (send, recv) = connection.accept_bi().await.expect("control");
    let mut channel = ControlChannel::new(tokio::io::join(recv, send));
    let mut handshake = ServerHandshake::new(
        "localhost",
        Limits { max_binds: 8, max_streams: 8 },
        None,
        |candidate| {
            if candidate == public_key { KeyDecision::Authorized } else { KeyDecision::Unknown }
        },
    );
    for _ in 0..2 {
        let frame = channel.recv().await.expect("handshake frame");
        match handshake.step(&frame).expect("handshake step") {
            HandshakeStep::Reply(reply) => channel.send(&reply).await.expect("reply"),
            HandshakeStep::Done { reply: Some(reply), .. } => {
                channel.send(&reply).await.expect("welcome");
            }
            step => panic!("unexpected handshake step: {step:?}"),
        }
    }
    let mut binds = HashMap::new();
    while let Ok(frame) = channel.recv().await {
        match frame {
            ControlFrame::Bind { request, spec: BindSpec::Tcp { remote_port, .. }, .. } => {
                let marker = remote_port.expect("marker");
                let bind = Uuid::now_v7();
                binds.insert(bind, marker);
                channel
                    .send(&ControlFrame::Bound {
                        request,
                        bind,
                        urls: vec![format!("tcp://localhost:{marker}")],
                        persist: Persistence::Temporary,
                        reservation: None,
                        pending_buffered: 0,
                        failed_buffered: 0,
                    })
                    .await
                    .expect("bound");
            }
            ControlFrame::BindReady { bind } => {
                channel.send(&ControlFrame::BindActive { bind }).await.expect("active");
                open_fake_stream(connection.clone(), bind, binds[&bind], results.clone());
            }
            ControlFrame::Ping { seq } => {
                channel.send(&ControlFrame::Pong { seq }).await.expect("pong");
            }
            ControlFrame::Unbind { bind, .. } => {
                binds.remove(&bind);
                channel.send(&ControlFrame::Unbound { bind }).await.expect("unbound");
                if let Some((&remaining, &marker)) = binds.iter().next() {
                    open_fake_stream(connection.clone(), remaining, marker, results.clone());
                }
            }
            ControlFrame::ForgetReservation { reservation } => {
                channel
                    .send(&ControlFrame::ForgotReservation { reservation })
                    .await
                    .expect("forgot reservation");
            }
            _ => {}
        }
    }
}

fn open_fake_stream(
    connection: quinn::Connection,
    bind: Uuid,
    marker: u16,
    results: mpsc::Sender<(u16, Vec<u8>)>,
) {
    tokio::spawn(async move {
        let (mut send, mut recv) = connection.open_bi().await.expect("data stream");
        write_stream_header(
            &mut send,
            &StreamHeader::Tcp { bind, peer: "127.0.0.1:12345".parse().expect("peer") },
        )
        .await
        .expect("header");
        send.write_all(b"request").await.expect("request");
        send.finish().expect("finish");
        let response = recv.read_to_end(1024).await.expect("response");
        results.send((marker, response)).await.expect("result");
    });
}
