use std::{fs, process::Command};

use super::infer;

#[test]
fn package_name_and_non_default_branch_are_inferred() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(directory.path().join("package.json"), r#"{"name":"Web App"}"#).expect("package");
    git(directory.path(), &["init", "-b", "main"]);

    assert_eq!(infer(None, directory.path()), "web-app");

    git(directory.path(), &["checkout", "-b", "fix/ui"]);
    assert_eq!(infer(None, directory.path()), "web-app-fix-ui");
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
