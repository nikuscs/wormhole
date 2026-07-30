use std::{fs, os::unix::fs::PermissionsExt as _};

use redb::{Database, TableDefinition};
use tempfile::tempdir;
use wormhole_core::{EndpointSpec, Service, Target, model::ServiceProto};
use wormhole_proto::frames::Persistence;

use super::{
    CURRENT_SCHEMA, DesiredKey, DesiredService, META, SCHEMA_KEY, SERVICES, StateDb, StateDbError,
};

#[test]
fn desired_services_round_trip_delete_and_permissions() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(path).expect("open");
    let desired = desired("project", "web");

    database.put(&desired).expect("put");

    let database_path = path.join("state.redb");
    assert!(database_path.exists());
    assert_eq!(fs::metadata(path).expect("dir metadata").permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(&database_path).expect("db metadata").permissions().mode() & 0o777,
        0o600
    );
    let restored = database.list().expect("list");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].service.name, "web");
    let key = DesiredKey::new("project".to_owned(), "web".to_owned()).expect("key");
    assert!(key.matches_project_target("project:web"));
    assert!(!key.matches_project_target("web"));
    assert!(database.delete(&key).expect("delete"));
    assert!(!database.delete(&key).expect("already deleted"));
    assert!(database.list().expect("empty").is_empty());
}

#[test]
fn put_replaces_legacy_key_without_leaving_duplicate_state() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(path).expect("open");
    let desired = desired("project", "web");
    let encoded = serde_json::to_vec(&desired).expect("encode");
    let raw = Database::create(path.join("legacy.redb")).expect("raw database");
    {
        let write = raw.begin_write().expect("write");
        {
            let mut table = write.open_table(SERVICES).expect("services");
            table.insert("project:web", encoded.as_slice()).expect("legacy row");
        }
        write.commit().expect("commit");
    }
    drop(raw);

    let legacy = StateDb { database: Database::create(path.join("legacy.redb")).expect("reopen") };
    legacy.put(&desired).expect("replace");
    assert_eq!(legacy.list().expect("list").len(), 1);
    assert!(legacy.delete(&desired.key().expect("key")).expect("delete"));
    drop(database);
}

#[test]
fn opening_legacy_schema_creates_backup_and_preserves_rows() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database_path = path.join("state.redb");
    let raw = Database::create(&database_path).expect("raw database");
    let desired = desired("project", "legacy");
    let encoded = serde_json::to_vec(&desired).expect("encode");
    {
        let write = raw.begin_write().expect("write");
        {
            let mut table = write.open_table(SERVICES).expect("services");
            table.insert("project:legacy", encoded.as_slice()).expect("row");
        }
        write.commit().expect("commit");
    }
    drop(raw);

    let database = StateDb::open(path).expect("migrate");
    assert_eq!(database.list().expect("list")[0].service.name, "legacy");
    let backups = fs::read_dir(path.join("backups")).expect("backups").count();
    assert_eq!(backups, 1);
}

#[test]
fn newer_schema_is_rejected_without_mutation() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let raw = Database::create(path.join("state.redb")).expect("raw database");
    {
        let write = raw.begin_write().expect("write");
        {
            let mut meta = write.open_table(META).expect("meta");
            meta.insert(SCHEMA_KEY, CURRENT_SCHEMA + 1).expect("schema");
        }
        write.commit().expect("commit");
    }
    drop(raw);

    assert!(
        matches!(StateDb::open(path), Err(StateDbError::NewerSchema(version)) if version == CURRENT_SCHEMA + 1)
    );
}

#[test]
fn corrupt_rows_are_reported_as_invalid_state() {
    const TEST_SERVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("services");
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(path).expect("open");
    {
        let write = database.database.begin_write().expect("write");
        {
            let mut table = write.open_table(TEST_SERVICES).expect("services");
            table.insert("bad", b"not-json".as_slice()).expect("bad row");
        }
        write.commit().expect("commit");
    }
    assert!(matches!(database.list(), Err(StateDbError::Data(_))));
}

#[test]
fn desired_keys_are_collision_free_and_validate_addressable_names() {
    let first = DesiredKey::new("a".to_owned(), "b:c".to_owned()).expect("first");
    let second = DesiredKey::new("a".to_owned(), "b".to_owned()).expect("second");

    assert_ne!(first, second);
    assert!(DesiredKey::new(String::new(), String::new()).is_err());
    assert!(DesiredKey::new("a:b".to_owned(), "c".to_owned()).is_err());
    assert!(DesiredKey::new("a\n".to_owned(), "c".to_owned()).is_err());
    assert!(DesiredKey::new(String::new(), "a/b".to_owned()).is_ok());
    assert!(
        !DesiredKey::new(String::new(), "service".to_owned())
            .expect("key")
            .matches_project_target(":service")
    );
}

fn desired(project: &str, name: &str) -> DesiredService {
    DesiredService {
        active: true,
        project_id: project.to_owned(),
        remotes: None,
        default_remote: None,
        service: Service {
            name: name.to_owned(),
            target: Target::Port(3000),
            proto: ServiceProto::Http,
        },
        endpoints: vec![EndpointSpec {
            proto: ServiceProto::Http,
            driver: "wormhole".to_owned(),
            qualifier: None,
            remote: Some("local".to_owned()),
            host: Some("web".to_owned()),
            auto_host: false,
            domain: None,
            public_port: None,
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
            retry: None,
            inspect: false,
            inspect_assets: false,
            capture_body_max: 1024 * 1024,
            reservation: None,
        }],
        disabled_endpoints: Vec::new(),
    }
}
