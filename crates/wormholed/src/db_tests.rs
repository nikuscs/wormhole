use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use jiff::Timestamp;
use redb::Database;
use tempfile::tempdir;
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, Persistence};

use super::{
    AuthorizedKey, CURRENT_SCHEMA, DbError, FailedWebhook, PersistedBind, PersistedBindSpec,
    PersistedEndpoint, RelayDb, initialize_schema, retain_latest_backups,
};

fn temporary_path() -> (tempfile::TempDir, Utf8PathBuf) {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    (directory, path)
}

fn bind() -> PersistedBind {
    let now = Timestamp::now();
    PersistedBind {
        reservation: Uuid::from_u128(2),
        spec: PersistedBindSpec::Http {
            host: Some("demo".to_owned()),
            domain: Some("tun.example.com".to_owned()),
            persist: Persistence::Persistent,
            buffer: Some(BufferPolicy { max_requests: 10, max_body_bytes: 4096, ttl_secs: 60 }),
        },
        auth_verifier: None,
        endpoint: PersistedEndpoint::Hostname("demo.tun.example.com".to_owned()),
        key_fpr: "WH256:owner".to_owned(),
        created: now,
        last_seen: now,
    }
}

#[test]
fn typed_crud_round_trips_all_tables() {
    let (_directory, path) = temporary_path();
    let database = RelayDb::open(&path).expect("database must open");
    let bind_id = Uuid::from_u128(1);
    let key = AuthorizedKey {
        pub_b64: "cHVibGljLWtleS0zMi1ieXRlcy1sb25nISEhISEhISE=".to_owned(),
        name: "deploy".to_owned(),
        created: Timestamp::now(),
        revoked: false,
    };
    let failed = FailedWebhook {
        request: b"request".to_vec(),
        reason: "offline".to_owned(),
        failed_at: Timestamp::now(),
    };
    let stored_bind = bind();

    database.put_bind(bind_id, &stored_bind).expect("bind must write");
    database.put_key("WH256:key", &key).expect("key must write");
    database.put_buffered(bind_id, 7, b"request").expect("buffer must write");
    database.put_failed(bind_id, 8, &failed).expect("failed record must write");

    assert_eq!(database.get_bind(bind_id).expect("bind must read"), Some(stored_bind));
    assert_eq!(database.list_binds().expect("binds must list").len(), 1);
    assert_eq!(database.get_key("WH256:key").expect("key must read"), Some(key));
    assert_eq!(database.list_keys().expect("keys must list").len(), 1);
    assert_eq!(
        database.get_buffered(bind_id, 7).expect("buffer must read"),
        Some(b"request".to_vec())
    );
    assert_eq!(database.get_failed(bind_id, 8).expect("failed must read"), Some(failed));
    assert!(database.delete_buffered(bind_id, 7).expect("buffer must delete"));
    assert!(database.delete_bind(bind_id).expect("bind must delete"));
}

#[test]
fn old_schema_is_backed_up_and_migrated() {
    let (_directory, path) = temporary_path();
    let database_path = path.join("state.redb");
    let database = Database::create(&database_path).expect("old database must create");
    initialize_schema(&database, 0).expect("old schema must initialize");
    drop(database);

    let migrated = RelayDb::open(&path).expect("old schema must migrate");
    drop(migrated);

    let backups = fs::read_dir(path.join("backups")).expect("backup directory must exist");
    assert_eq!(backups.count(), 1);
    RelayDb::open(&path).expect("migrated database must reopen");
}

#[test]
fn newer_schema_is_refused() {
    let (_directory, path) = temporary_path();
    let database = Database::create(path.join("state.redb")).expect("database must create");
    initialize_schema(&database, CURRENT_SCHEMA + 1).expect("future schema must initialize");
    drop(database);

    let Err(error) = RelayDb::open(&path) else {
        panic!("future schema must fail");
    };

    assert!(matches!(
        error,
        DbError::NewerSchema { found, supported }
            if found == CURRENT_SCHEMA + 1 && supported == CURRENT_SCHEMA
    ));
}

#[test]
fn only_latest_two_backups_are_retained() {
    let (_directory, path) = temporary_path();
    let backups = path.join("backups");
    fs::create_dir(&backups).expect("backup directory must create");
    for index in 0..3 {
        fs::write(backups.join(format!("state-v0-{index}.redb")), index.to_string())
            .expect("backup fixture must write");
    }

    retain_latest_backups(&backups).expect("backups must prune");

    assert_eq!(fs::read_dir(backups).expect("backups must list").count(), 2);
}
