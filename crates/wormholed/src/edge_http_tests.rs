use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use super::{HttpRedirectEdge, allowed_host, redirect_location};

#[test]
fn redirect_location_and_host_policy_cover_public_authorities() {
    assert_eq!(
        redirect_location("demo.tun.example.com", "/hooks?event=push", 8443),
        "https://demo.tun.example.com:8443/hooks?event=push"
    );
    assert_eq!(
        redirect_location("demo.tun.example.com", "/", 443),
        "https://demo.tun.example.com/"
    );
    let domains = ["tun.example.com".to_owned()];
    assert!(allowed_host("DEMO.tun.example.com", &domains));
    assert!(allowed_host("tun.example.com.", &domains));
    assert!(!allowed_host("evil.example", &domains));
    assert!(!allowed_host("a.b.tun.example.com", &domains));
    assert!(!allowed_host("eviltun.example.com", &domains));
}

#[test]
fn redirect_includes_nonstandard_https_port_and_path() {
    assert_eq!(
        redirect_location("demo.tun.example.com", "/hooks?event=push", 8443),
        "https://demo.tun.example.com:8443/hooks?event=push"
    );
    assert_eq!(
        redirect_location("demo.tun.example.com", "/", 443),
        "https://demo.tun.example.com/"
    );
    let domains = ["tun.example.com".to_owned()];
    assert!(allowed_host("DEMO.tun.example.com", &domains));
    assert!(allowed_host("tun.example.com", &domains));
    assert!(!allowed_host("evil.example", &domains));
    assert!(!allowed_host("a.b.tun.example.com", &domains));
}

#[tokio::test]
async fn listener_redirects_allowed_hosts_and_rejects_others() {
    let edge = Arc::new(
        HttpRedirectEdge::bind(
            "127.0.0.1:0".parse().expect("address"),
            8443,
            vec!["tun.example.com".to_owned()],
        )
        .await
        .expect("bind redirect edge"),
    );
    let address = edge.local_addr().expect("local address");
    let task = tokio::spawn({
        let edge = Arc::clone(&edge);
        async move { edge.run().await }
    });

    let redirected = exchange(
        address,
        "GET /hooks?event=push HTTP/1.1\r\nHost: demo.tun.example.com:8080\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(redirected.starts_with("HTTP/1.1 308 Permanent Redirect"));
    assert!(
        redirected
            .to_ascii_lowercase()
            .contains("location: https://demo.tun.example.com:8443/hooks?event=push")
    );

    let missing = exchange(
        address,
        "GET / HTTP/1.1\r\nHost: deep.demo.tun.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(missing.starts_with("HTTP/1.1 404 Not Found"));

    let absent = exchange(address, "GET / HTTP/1.0\r\n\r\n").await;
    assert!(absent.starts_with("HTTP/1.0 404 Not Found"));
    task.abort();
}

#[tokio::test]
async fn bind_reports_address_in_use() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("occupied listener");
    let address = occupied.local_addr().expect("address");
    assert!(HttpRedirectEdge::bind(address, 443, vec![]).await.is_err());
}

async fn exchange(address: std::net::SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read response");
    String::from_utf8(response).expect("UTF-8 response")
}
