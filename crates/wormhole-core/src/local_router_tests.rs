use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

use super::LocalRouter;
use crate::local_ca::{LocalCertResolver, LocalCertificateAuthority};

#[tokio::test]
async fn routes_requests_by_normalized_host_and_removes_last_listener() {
    let first = target_server(b"first").await;
    let second = target_server(b"second").await;
    let router = std::sync::Arc::new(LocalRouter::new());
    let first_route = router.register(0, "One.Localhost", first).await.expect("first route");
    let address = first_route.listener_address().await.expect("listener address");
    let second_route = router.register(0, "two.localhost", second).await.expect("second route");

    assert_eq!(request(address, "one.localhost:8123").await, "first");
    assert_eq!(request(address, "TWO.LOCALHOST").await, "second");
    assert_eq!(status(address, "missing.localhost").await, "HTTP/1.1 404 Not Found");

    first_route.close().await;
    assert_eq!(request(address, "two.localhost").await, "second");
    second_route.close().await;
    let rebound = TcpListener::bind(address).await.expect("last route released listener");
    drop(rebound);
}

#[tokio::test]
async fn binary_post_body_routes_and_reaches_upstream_intact() {
    let target = echo_body_server().await;
    let router = std::sync::Arc::new(LocalRouter::new());
    let route = router.register(0, "upload.localhost", target).await.expect("route");
    let address = route.listener_address().await.expect("listener address");
    let body = [0_u8, 159, 146, 150, 255, 1, 2, 3];

    let response = binary_exchange(address, "upload.localhost", &body).await;

    let boundary = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").expect("head");
    assert_eq!(&response[boundary + 4..], body);
    route.close().await;
}

#[tokio::test]
async fn https_uses_sni_certificate_and_routes_by_host() {
    let target = target_server(b"secure").await;
    let directory = tempfile::tempdir().expect("CA directory");
    let root = camino::Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let authority =
        std::sync::Arc::new(LocalCertificateAuthority::load_or_create(root).expect("local CA"));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(authority.certificate_der()).expect("trusted CA");
    let resolver = std::sync::Arc::new(LocalCertResolver::new(authority));
    let router = std::sync::Arc::new(LocalRouter::new());
    let route =
        router.register_https(0, "secure.localhost", target, resolver).await.expect("HTTPS route");
    let address = route.listener_address().await.expect("HTTPS address");

    let config =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(address).await.expect("TLS connection");
    let name = rustls::pki_types::ServerName::try_from("secure.localhost")
        .expect("server name")
        .to_owned();
    let mut stream = connector.connect(name, stream).await.expect("TLS handshake");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: secure.localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request");
    stream.shutdown().await.expect("request shutdown");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("response");

    assert_eq!(response.split_once("\r\n\r\n").expect("response head").1, "secure");
    route.close().await;
}

#[tokio::test]
async fn rejects_duplicate_hostname_without_replacing_the_route() {
    let first = target_server(b"first").await;
    let second = target_server(b"second").await;
    let router = std::sync::Arc::new(LocalRouter::new());
    let route = router.register(0, "app.localhost", first).await.expect("route");
    let address = route.listener_address().await.expect("listener address");

    assert!(router.register(0, "APP.LOCALHOST", second).await.is_err());
    assert_eq!(request(address, "app.localhost").await, "first");
    route.close().await;
}

async fn target_server(body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("target listener");
    let address = listener.local_addr().expect("target address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0_u8; 1024];
            let _read = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                let _written = stream.write_all(body).await;
            }
        }
    });
    address
}

async fn echo_body_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("target listener");
    let address = listener.local_addr().expect("target address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upload connection");
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.expect("upload request");
        let boundary = request.windows(4).position(|bytes| bytes == b"\r\n\r\n").expect("head");
        let body = &request[boundary + 4..];
        let response = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.expect("response head");
        stream.write_all(body).await.expect("response body");
    });
    address
}

async fn binary_exchange(address: SocketAddr, host: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("router connection");
    let head = format!(
        "POST /upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("request head");
    stream.write_all(body).await.expect("request body");
    stream.shutdown().await.expect("request shutdown");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("response");
    response
}

async fn request(address: SocketAddr, host: &str) -> String {
    let response = exchange(address, host).await;
    response.split_once("\r\n\r\n").expect("response head").1.to_owned()
}

async fn status(address: SocketAddr, host: &str) -> String {
    exchange(address, host).await.lines().next().expect("status line").to_owned()
}

async fn exchange(address: SocketAddr, host: &str) -> String {
    let mut stream = TcpStream::connect(address).await.expect("router connection");
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("request");
    stream.shutdown().await.expect("request shutdown");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("response");
    response
}
