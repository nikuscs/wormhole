use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::{RuntimeError, RuntimePaths, current_uid, fallback_state_dir, open_private};

#[test]
fn runtime_owner_uses_effective_uid() {
    assert_eq!(current_uid(), nix::unistd::geteuid().as_raw());
}

#[test]
fn platform_fallback_uses_the_user_state_directory() {
    let path = fallback_state_dir().expect("fallback state directory");
    #[cfg(target_os = "macos")]
    assert!(path.ends_with("Library/Application Support/wormhole"));
    #[cfg(not(target_os = "macos"))]
    assert!(path.ends_with(".local/state/wormhole"));
}

#[test]
fn runtime_paths_prepare_private_directory_and_files() {
    let directory = tempfile::tempdir().expect("tempdir");
    let state_dir = camino::Utf8PathBuf::from_path_buf(directory.path().join("nested/state"))
        .expect("UTF-8 path");
    let paths = RuntimePaths {
        socket: state_dir.join("daemon.sock"),
        lock: state_dir.join("daemon.lock"),
        token: state_dir.join("api-token"),
        log: state_dir.join("daemon.log"),
        state_dir: state_dir.clone(),
    };

    paths.prepare().expect("create runtime directory");
    paths.prepare().expect("verify existing runtime directory");
    assert_eq!(
        std::fs::metadata(&state_dir).expect("metadata").permissions().mode() & 0o777,
        0o700
    );

    std::fs::write(&paths.token, b"old-token").expect("token");
    let file = open_private(&paths.token, true).expect("private token");
    assert_eq!(file.metadata().expect("metadata").permissions().mode() & 0o777, 0o600);
    assert_eq!(file.metadata().expect("metadata").len(), 0);
}

#[test]
fn runtime_paths_reject_non_directories_and_symlinked_files() {
    let directory = tempfile::tempdir().expect("tempdir");
    let unsafe_path = camino::Utf8PathBuf::from_path_buf(directory.path().join("not-a-directory"))
        .expect("UTF-8 path");
    std::fs::write(&unsafe_path, b"file").expect("file");
    let paths = RuntimePaths {
        socket: unsafe_path.join("daemon.sock"),
        lock: unsafe_path.join("daemon.lock"),
        token: unsafe_path.join("api-token"),
        log: unsafe_path.join("daemon.log"),
        state_dir: unsafe_path.clone(),
    };
    assert!(
        matches!(paths.prepare(), Err(RuntimeError::UnsafeDirectory(path)) if path == unsafe_path)
    );

    let target =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("target")).expect("UTF-8 path");
    let link =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("link")).expect("UTF-8 path");
    std::fs::write(&target, b"secret").expect("target");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(matches!(open_private(&link, false), Err(RuntimeError::Io(_))));
    assert_eq!(std::fs::metadata(target).expect("metadata").uid(), current_uid());
}
