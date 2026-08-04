use std::{fs, path::Path, process::Command};

use super::{infer, worktree_slug};

#[test]
fn package_name_and_non_default_branch_are_inferred() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(directory.path().join("package.json"), r#"{"name":"Web App"}"#).expect("package");

    assert_eq!(infer(None, directory.path()), "web-app");
}

#[test]
fn the_repository_name_outranks_a_scoped_package_name() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    git(root, &["remote", "add", "origin", "https://github.com/acme/social-farmer.git"]);
    let nested = root.join("apps").join("web");
    fs::create_dir_all(&nested).expect("nested");
    fs::write(nested.join("package.json"), r#"{"name":"@app/web"}"#).expect("package");

    assert_eq!(infer(None, root), "social-farmer");
    assert_eq!(infer(None, &nested), "social-farmer-web");
}

#[test]
fn a_non_default_branch_is_appended() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    git(root, &["remote", "add", "origin", "https://github.com/acme/shop.git"]);

    assert_eq!(infer(None, root), "shop");

    git(root, &["checkout", "-q", "-b", "fix/ui"]);
    assert_eq!(infer(None, root), "shop-fix-ui");
}

#[test]
fn a_repository_configuration_names_every_subdirectory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    fs::write(root.join("wormhole.toml"), "name = \"shop\"\n").expect("config");
    let nested = root.join("apps").join("web");
    fs::create_dir_all(&nested).expect("nested");
    fs::write(nested.join("package.json"), r#"{"name":"@app/web"}"#).expect("package");

    assert_eq!(infer(None, &nested), "shop");
}

#[test]
fn templates_expand_repository_and_service_placeholders() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    git(root, &["remote", "add", "origin", "https://github.com/acme/shop.git"]);
    fs::write(root.join("wormhole.toml"), "name = \"{repo}-{service}\"\n").expect("config");

    assert_eq!(worktree_slug(None, "api", root), "shop-api");
}

#[test]
fn a_branch_template_replaces_the_automatic_suffix() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    init(root);
    git(root, &["remote", "add", "origin", "https://github.com/acme/shop.git"]);
    fs::write(root.join("wormhole.toml"), "name = \"{branch}-{repo}\"\n").expect("config");
    git(root, &["checkout", "-q", "-b", "fix/ui"]);

    assert_eq!(infer(None, root), "fix-ui-shop");
}

#[test]
fn unknown_placeholders_stay_visible() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(directory.path().join("wormhole.toml"), "name = \"app-{nope}\"\n").expect("config");

    assert_eq!(infer(None, directory.path()), "app-nope");
}

#[test]
fn non_git_folders_use_package_or_directory_identity() {
    let first = tempfile::tempdir().expect("first");
    let second = tempfile::tempdir().expect("second");
    for directory in [&first, &second] {
        fs::write(directory.path().join("package.json"), r#"{"name":"Store Front"}"#)
            .expect("package");
    }

    assert_eq!(worktree_slug(None, "web", first.path()), "store-front-web");
    assert_eq!(worktree_slug(None, "web", first.path()), worktree_slug(None, "web", second.path()));
    assert_eq!(worktree_slug(Some("---"), "", first.path()), "app");
}

#[test]
fn long_slugs_are_valid_stable_and_collision_resistant() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first = worktree_slug(
        Some("extremely-long-project-name-that-would-overflow-a-single-dns-label"),
        "frontend-service-one",
        directory.path(),
    );
    let second = worktree_slug(
        Some("extremely-long-project-name-that-would-overflow-a-single-dns-label"),
        "frontend-service-two",
        directory.path(),
    );

    assert!(first.len() <= 63);
    assert!(first.chars().all(|character| character.is_ascii_lowercase()
        || character.is_ascii_digit()
        || character == '-'));
    assert_ne!(first, second);
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
