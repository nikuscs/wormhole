use std::{fs, sync::Arc};

use camino::Utf8Path;
use tempfile::tempdir;
use wormhole_proto::{Identity, PublicKeyRef};

use super::{AuthStore, KeyDecision, KeyLimits};
use crate::db::RelayDb;

fn store(path: &Utf8Path) -> AuthStore {
    let database = Arc::new(RelayDb::open(path).expect("database must open"));
    AuthStore::new(database, KeyLimits { max_binds: 4, max_sessions: 2, max_streams: 32 })
}

#[test]
fn unseen_public_file_is_imported_once() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let imports = path.join("authorized_keys");
    fs::create_dir(&imports).expect("import directory must create");
    let identity = Identity::generate();
    fs::write(imports.join("deploy.pub"), format!("{} deploy key\n", identity.public_base64()))
        .expect("public file must write");
    let store = store(path);

    assert_eq!(store.import_directory(&imports).expect("first import must succeed"), 1);
    assert_eq!(store.import_directory(&imports).expect("second import must succeed"), 0);
    assert!(matches!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Allowed { name, .. } if name == "deploy key"
    ));
}

#[test]
fn revoked_database_row_wins_over_public_file() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let imports = path.join("authorized_keys");
    fs::create_dir(&imports).expect("import directory must create");
    let identity = Identity::generate();
    let store = store(path);
    let fingerprint =
        store.authorize(&identity.public_base64(), "revoked").expect("key must authorize");
    store.revoke(&fingerprint).expect("key must revoke");
    fs::write(imports.join("revoked.pub"), format!("{} resurrect\n", identity.public_base64()))
        .expect("public file must write");

    assert_eq!(store.import_directory(&imports).expect("import must succeed"), 0);
    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Revoked
    );
}

#[test]
fn authorize_and_revoke_update_authoritative_state() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path");
    let identity = Identity::generate();
    let store = store(path);

    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Unknown
    );
    let fingerprint =
        store.authorize(&identity.public_base64(), "agent").expect("key must authorize");
    let expected = PublicKeyRef::parse(&identity.public_base64())
        .expect("generated key must parse")
        .fingerprint();
    assert_eq!(fingerprint, expected);
    assert!(matches!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Allowed { name, limits, .. }
            if name == "agent" && limits.max_binds == 4
    ));

    store.revoke(&fingerprint).expect("key must revoke");
    assert_eq!(
        store.is_authorized(&identity.public_base64()).expect("lookup must succeed"),
        KeyDecision::Revoked
    );
}
