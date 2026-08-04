//! Repository-aware discovery of `wormhole.toml` and git identity.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Nearest `wormhole.toml` at or above `directory`, never escaping the repository.
///
/// Monorepo subdirectories inherit the repository-root configuration; a directory outside any
/// repository only considers itself.
pub fn config_path(directory: &Path) -> Option<PathBuf> {
    let start = canonical(directory);
    let ceiling = toplevel(directory).map(|path| canonical(&path));
    let mut current = Some(start.as_path());
    while let Some(entry) = current {
        let candidate = entry.join("wormhole.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if ceiling.as_deref() == Some(entry) {
            return None;
        }
        current = entry.parent();
    }
    None
}

/// Repository root of `directory`, or `None` outside a repository.
pub fn toplevel(directory: &Path) -> Option<PathBuf> {
    git(directory, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

/// Repository name, preferring the `origin` remote over the checkout directory.
///
/// The remote is authoritative because linked worktrees and local clones are routinely renamed.
pub fn repo_name(directory: &Path) -> Option<String> {
    git(directory, &["remote", "get-url", "origin"])
        .and_then(|url| remote_name(&url))
        .or_else(|| directory_name(&toplevel(directory)?))
}

/// Checkout directory name, which differs from [`repo_name`] inside a linked worktree.
pub fn worktree_name(directory: &Path) -> Option<String> {
    directory_name(&toplevel(directory)?)
}

/// Current branch, or `None` when detached or outside a repository.
pub fn branch(directory: &Path) -> Option<String> {
    git(directory, &["branch", "--show-current"]).filter(|branch| !branch.is_empty())
}

/// Whether `branch` is the repository's default branch.
pub fn is_default_branch(directory: &Path, branch: &str) -> bool {
    let default = git(directory, &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .and_then(|value| value.rsplit('/').next().map(str::to_owned));
    default.map_or_else(|| matches!(branch, "main" | "master"), |default| branch == default)
}

/// Directory name of `directory` relative to the repository root, or `None` at the root itself.
pub fn scope_name(directory: &Path) -> Option<String> {
    let root = canonical(&toplevel(directory)?);
    let current = canonical(directory);
    (current != root).then(|| directory_name(&current)).flatten()
}

fn remote_name(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let name = trimmed.strip_suffix(".git").unwrap_or(trimmed).rsplit(['/', ':']).next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn directory_name(path: &Path) -> Option<String> {
    path.file_name().and_then(|name| name.to_str()).map(str::to_owned)
}

fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn git(directory: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
#[path = "project_root_tests.rs"]
mod tests;
