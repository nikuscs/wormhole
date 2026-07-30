//! Worktree-aware service-name inference.

use std::{fmt::Write as _, fs, path::Path, process::Command};

use sha2::{Digest as _, Sha256};

pub fn infer(explicit: Option<&str>, directory: &Path) -> String {
    finish_label(&base_name(explicit, directory), directory)
}

pub fn worktree_slug(project: Option<&str>, service: &str, directory: &Path) -> String {
    let base = base_name(project, directory);
    let seed = if service.is_empty() || sanitize(service) == sanitize(&base) {
        base
    } else {
        format!("{base}-{service}")
    };
    finish_label(&seed, directory)
}

fn base_name(explicit: Option<&str>, directory: &Path) -> String {
    explicit
        .map(str::to_owned)
        .or_else(|| project_toml_name(directory))
        .or_else(|| package_name(directory))
        .or_else(|| directory.file_name().and_then(|name| name.to_str()).map(str::to_owned))
        .unwrap_or_else(|| "app".to_owned())
}

fn finish_label(base: &str, directory: &Path) -> String {
    let mut base = sanitize(base);
    if base.is_empty() {
        "app".clone_into(&mut base);
    }
    let value = match git_branch(directory) {
        Some(branch) if !is_default_branch(directory, &branch) => match sanitize(&branch) {
            branch if branch.is_empty() => base,
            branch => format!("{base}-{branch}"),
        },
        _ => base,
    };
    shorten_label(&value)
}

fn shorten_label(value: &str) -> String {
    if value.len() <= 63 {
        return value.to_owned();
    }
    let digest = Sha256::digest(value.as_bytes());
    let mut suffix = String::with_capacity(12);
    for byte in &digest[..6] {
        write!(suffix, "{byte:02x}").expect("writing to String cannot fail");
    }
    let prefix = value[..50].trim_end_matches('-');
    format!("{prefix}-{suffix}")
}

fn project_toml_name(directory: &Path) -> Option<String> {
    let value = fs::read_to_string(directory.join("wormhole.toml")).ok()?;
    value.parse::<toml::Value>().ok()?.get("name")?.as_str().map(str::to_owned)
}

fn package_name(directory: &Path) -> Option<String> {
    let value = fs::read(directory.join("package.json")).ok()?;
    serde_json::from_slice::<serde_json::Value>(&value)
        .ok()?
        .get("name")?
        .as_str()
        .map(str::to_owned)
}

fn git_branch(directory: &Path) -> Option<String> {
    git(directory, &["branch", "--show-current"]).filter(|branch| !branch.is_empty())
}

fn is_default_branch(directory: &Path, branch: &str) -> bool {
    let default = git(directory, &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .and_then(|value| value.rsplit('/').next().map(str::to_owned));
    default.map_or_else(|| matches!(branch, "main" | "master"), |default| branch == default)
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

fn sanitize(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut hyphen = false;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            hyphen = false;
        } else if !hyphen && !output.is_empty() {
            output.push('-');
            hyphen = true;
        }
    }
    output.trim_end_matches('-').to_owned()
}

#[cfg(test)]
#[path = "project_name_tests.rs"]
mod tests;
