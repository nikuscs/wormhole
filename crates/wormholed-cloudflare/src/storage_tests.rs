use super::SCHEMA;

#[test]
fn cleanup_queries_have_supporting_indexes() {
    assert!(SCHEMA.contains("CREATE INDEX IF NOT EXISTS binds_connection ON binds(connection_id)"));
    assert!(
        SCHEMA.contains("CREATE INDEX IF NOT EXISTS sessions_fingerprint ON sessions(fingerprint)")
    );
}
