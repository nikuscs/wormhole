use std::{fs, process::Command};

use super::{infer, worktree_slug};

#[test]
fn package_name_and_non_default_branch_are_inferred() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(directory.path().join("package.json"), r#"{"name":"Web App"}"#).expect("package");
    git(directory.path(), &["init", "-b", "main"]);

    assert_eq!(infer(None, directory.path()), "web-app");

    git(directory.path(), &["checkout", "-b", "fix/ui"]);
    assert_eq!(infer(None, directory.path()), "web-app-fix-ui");
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

fn git(directory: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git");
    assert!(status.success());
}
