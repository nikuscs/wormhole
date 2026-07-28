use super::Remote;

#[tokio::test]
async fn resolves_valid_authority_and_reports_invalid_host() {
    let remote = Remote::new("127.0.0.1:443".to_owned(), "localhost".to_owned(), None);
    assert_eq!(remote.resolve_addr().await.expect("resolve").port(), 443);
    let invalid = Remote::new("invalid host name:443".to_owned(), "localhost".to_owned(), None);
    assert!(invalid.resolve_addr().await.is_err());
}
