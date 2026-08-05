use super::SCHEMA;

#[test]
fn cleanup_queries_have_supporting_indexes() {
    assert!(SCHEMA.contains("CREATE INDEX IF NOT EXISTS binds_connection ON binds(connection_id)"));
    assert!(
        SCHEMA.contains("CREATE INDEX IF NOT EXISTS sessions_fingerprint ON sessions(fingerprint)")
    );
}

#[test]
fn idle_sweeps_have_a_supporting_index_and_a_recorded_activity_column() {
    assert!(SCHEMA.contains("last_active_at INTEGER NOT NULL DEFAULT 0"));
    assert!(
        SCHEMA.contains("CREATE INDEX IF NOT EXISTS binds_idle ON binds(state,last_active_at)")
    );
}

#[test]
fn every_added_column_is_also_present_for_fresh_objects() {
    // An object created today runs SCHEMA only, so a column that exists solely as a migration
    // would be missing there and every query touching it would fail.
    for (table, column, _) in super::ADDED_COLUMNS {
        assert!(SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")));
        assert!(SCHEMA.contains(column), "{column} missing from the base schema");
    }
}
