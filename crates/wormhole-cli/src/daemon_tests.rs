use std::{fs, os::unix::fs::PermissionsExt as _};

use tempfile::tempdir;

use crate::runtime::RuntimePaths;

use super::{read_token, remove_stale_socket, write_token};

#[test]
fn token_is_private_and_round_trips() {
    let directory = tempdir().expect("tempdir");
    let state_dir = camino::Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("utf8");
    let paths = RuntimePaths {
        socket: state_dir.join("daemon.sock"),
        lock: state_dir.join("daemon.lock"),
        token: state_dir.join("api-token"),
        log: state_dir.join("daemon.log"),
        state_dir,
    };

    let written = write_token(&paths).expect("write token");

    assert_eq!(read_token(&paths).expect("read token"), written);
    let mode = fs::metadata(&paths.token).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn stale_socket_cleanup_refuses_regular_files() {
    let directory = tempdir().expect("tempdir");
    let path =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("daemon.sock")).expect("utf8");
    fs::write(&path, b"not a socket").expect("file");

    assert!(remove_stale_socket(&path).is_err());
    assert!(path.exists());
}
