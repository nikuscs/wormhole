use super::read_log;

#[tokio::test]
async fn missing_log_is_optional_but_other_read_errors_propagate() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = camino::Utf8Path::from_path(directory.path()).expect("utf8");

    assert!(read_log(&root.join("missing.log")).await.expect("missing optional").is_empty());
    assert!(read_log(root).await.is_err());
}
