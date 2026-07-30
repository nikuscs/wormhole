use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName, pem::PemObject as _},
};

use crate::harness::{TestClient, TestRelay};

#[test]
#[ignore = "e2e"]
fn tls_edge_rejects_slowloris_host_mismatch_and_no_sni() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    let config = tls_config(&relay);

    let mut stream = tls_stream(&relay, Arc::clone(&config), dns_name());
    assert_eq!(stream.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
    stream.sock.set_write_timeout(Some(Duration::from_secs(2))).expect("write timeout");
    let started = Instant::now();
    let mut closed = false;
    for byte in b"GET / HTTP/1.1\r\n".iter().take(12) {
        if stream.write_all(&[*byte]).and_then(|()| stream.flush()).is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if stream.sock.set_read_timeout(Some(Duration::from_secs(3))).is_err() {
        closed = true;
    } else {
        let mut byte = [0_u8; 1];
        closed |= stream.read(&mut byte).is_err() || byte[0] == 0;
    }
    assert!(closed, "absolute header timeout must close an active slowloris");
    assert!(started.elapsed() <= Duration::from_secs(15));

    let url = format!("https://wormhole.test:{}/health", relay.port);
    let mismatch = relay
        .request_with("wormhole.test", &url, &["--header", "Host: attacker.test"])
        .expect("mismatch request");
    assert_eq!(status(&mismatch.stdout), 421);

    let socket = TcpStream::connect(("127.0.0.1", relay.port)).expect("TLS edge");
    let name = ServerName::IpAddress(IpAddr::from([127, 0, 0, 1]).into());
    let mut no_sni = StreamOwned::new(ClientConnection::new(config, name).expect("client"), socket);
    assert!(no_sni.conn.complete_io(&mut no_sni.sock).is_err());
}

fn tls_config(relay: &TestRelay) -> Arc<ClientConfig> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&relay.certificate).expect("certificate") {
        roots.add(certificate.expect("PEM certificate")).expect("trusted certificate");
    }
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

fn tls_stream(
    relay: &TestRelay,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> StreamOwned<ClientConnection, TcpStream> {
    let socket = TcpStream::connect(("127.0.0.1", relay.port)).expect("TLS edge");
    let mut stream = StreamOwned::new(ClientConnection::new(config, name).expect("client"), socket);
    stream.conn.complete_io(&mut stream.sock).expect("TLS handshake");
    stream
}

fn dns_name() -> ServerName<'static> {
    ServerName::try_from("wormhole.test").expect("DNS name").to_owned()
}

fn status(output: &[u8]) -> u16 {
    String::from_utf8_lossy(output)
        .rsplit_once('\n')
        .and_then(|(_, status)| status.parse().ok())
        .unwrap_or(0)
}
