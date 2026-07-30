use std::os::unix::fs::PermissionsExt;

use camino::Utf8PathBuf;
use tempfile::tempdir;

use super::IdentityStore;
use crate::remotes::Remote;

fn remote(identity: Option<&str>) -> Remote {
    toml::from_str(&format!(
        "addr = \"localhost:443\"\nserver_name = \"localhost\"\n{}",
        identity.map_or_else(String::new, |path| format!("identity = \"{path}\"\n"))
    ))
    .expect("remote")
}

#[test]
fn identity_is_generated_once_with_private_permissions() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let store = IdentityStore::with_home(home);

    let first = store.resolve_identity(&remote(None)).expect("generated identity");
    let second = store.resolve_identity(&remote(None)).expect("loaded identity");

    assert_eq!(first.public_base64(), second.public_base64());
    let mode =
        std::fs::metadata(store.default_path()).expect("identity metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn default_identity_rotation_replaces_key_and_reports_fingerprints() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let store = IdentityStore::with_home(home);
    let before = store.default_identity().expect("default").fingerprint();
    let (old, new) = store.rotate_default().expect("rotate");
    assert_eq!(old, before);
    assert_ne!(new, old);
    assert_eq!(store.default_identity().expect("rotated").fingerprint(), new);
}

#[test]
fn remote_override_expands_home() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let store = IdentityStore::with_home(home.clone());

    store
        .resolve_identity(&remote(Some("~/.config/wormhole/keys/work.key")))
        .expect("override identity");

    assert!(home.join(".config/wormhole/keys/work.key").is_file());
}
