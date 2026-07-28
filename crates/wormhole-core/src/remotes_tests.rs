use super::Remote;

#[tokio::test]
async fn resolves_valid_authority_and_reports_invalid_host() {
    let remote = Remote::new("127.0.0.1:443".to_owned(), "localhost".to_owned(), None);
    assert!(remote.resolve_addrs().await.expect("resolve").iter().all(|addr| addr.port() == 443));
    let invalid = Remote::new("invalid host name:443".to_owned(), "localhost".to_owned(), None);
    assert!(invalid.resolve_addrs().await.is_err());
}
