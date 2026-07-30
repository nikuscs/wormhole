use std::time::Duration;

use tokio::io::AsyncReadExt as _;

use super::http_get_until;

#[tokio::test]
async fn metrics_read_cannot_outlive_discovery_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0_u8; 256];
        let _read = stream.read(&mut request).await.expect("request");
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let deadline = tokio::time::Instant::now() + Duration::from_millis(50);

    let error = http_get_until(port, "/quicktunnel", deadline)
        .await
        .expect_err("stalled metrics response must time out");

    assert!(error.to_string().contains("discovery deadline exceeded"));
    server.abort();
}
