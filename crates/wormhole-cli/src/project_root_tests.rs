use std::{fs, path::Path, process::Command};

use super::{config_path, repo_name, scope_name};

#[test]
fn nested_directories_inherit_the_repository_configuration() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    fs::write(root.join("wormhole.toml"), "name = \"shop\"\n").expect("config");
    let nested = root.join("apps").join("web");
    fs::create_dir_all(&nested).expect("nested");

    assert_eq!(
        config_path(&nested),
        Some(fs::canonicalize(root).expect("root").join("wormhole.toml"))
    );
}

#[test]
fn a_nearer_configuration_wins_over_the_repository_root() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    fs::write(root.join("wormhole.toml"), "name = \"shop\"\n").expect("root config");
    let nested = root.join("apps").join("web");
    fs::create_dir_all(&nested).expect("nested");
    fs::write(nested.join("wormhole.toml"), "name = \"web\"\n").expect("nested config");

    assert_eq!(
        config_path(&nested),
        Some(fs::canonicalize(&nested).expect("nested").join("wormhole.toml"))
    );
}

#[test]
fn the_walk_stops_at_the_repository_boundary() {
    let directory = tempfile::tempdir().expect("tempdir");
    let outer = directory.path();
    fs::write(outer.join("wormhole.toml"), "name = \"outer\"\n").expect("outer config");
    let inner = outer.join("repo");
    fs::create_dir_all(&inner).expect("inner");
    init(&inner);

    assert_eq!(config_path(&inner), None);
}

#[test]
fn the_origin_remote_names_the_repository() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    git(root, &["remote", "add", "origin", "https://github.com/acme/social-farmer.git"]);

    assert_eq!(repo_name(root).as_deref(), Some("social-farmer"));
    assert_eq!(scope_name(root), None);
}

#[test]
fn a_subdirectory_reports_its_own_scope() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    let nested = root.join("apps").join("web");
    fs::create_dir_all(&nested).expect("nested");

    assert_eq!(scope_name(&nested).as_deref(), Some("web"));
}

fn init(directory: &Path) {
    git(directory, &["init", "-b", "main"]);
}

fn git(directory: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git");
    assert!(status.success());
}
