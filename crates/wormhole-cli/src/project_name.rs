//! Worktree-aware service-name inference.

use std::{fmt::Write as _, fs, path::Path};

use sha2::{Digest as _, Sha256};

use crate::project_root;

/// Placeholders accepted in a `wormhole.toml` `name` template.
const PLACEHOLDERS: [&str; 5] = ["repo", "branch", "service", "dir", "worktree"];

pub fn infer(explicit: Option<&str>, directory: &Path) -> String {
    resolve(explicit, "", directory)
}

pub fn worktree_slug(project: Option<&str>, service: &str, directory: &Path) -> String {
    resolve(project, service, directory)
}

fn resolve(explicit: Option<&str>, service: &str, directory: &Path) -> String {
    let source = base_name(explicit, directory);
    let expanded = expand(&source.scope(directory), service, directory);
    let base = sanitize(&expanded.value);
    let base = if base.is_empty() { "app".to_owned() } else { base };
    let seed = if service.is_empty() || expanded.used_service || sanitize(service) == base {
        base
    } else {
        format!("{base}-{service}")
    };
    let value = if expanded.used_branch { sanitize(&seed) } else { with_branch(&seed, directory) };
    shorten_label(&if value.is_empty() { "app".to_owned() } else { value })
}

struct Base {
    value: String,
    /// Repository-derived names are shared by every directory in the repository, so a monorepo
    /// subdirectory must contribute its own scope to stay unique.
    scoped: bool,
}

struct Expanded {
    value: String,
    /// A template placing a value itself owns that decision; appending again would duplicate it.
    used_branch: bool,
    used_service: bool,
}

fn base_name(explicit: Option<&str>, directory: &Path) -> Base {
    if let Some(value) = explicit {
        return Base { value: value.to_owned(), scoped: false };
    }
    if let Some(value) = project_toml_name(directory) {
        return Base { value, scoped: false };
    }
    if let Some(value) = project_root::repo_name(directory) {
        return Base { value, scoped: true };
    }
    if let Some(value) = package_name(directory) {
        return Base { value, scoped: false };
    }
    let value = directory
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "app".to_owned(), str::to_owned);
    Base { value, scoped: false }
}

impl Base {
    fn scope(&self, directory: &Path) -> String {
        self.scoped
            .then(|| project_root::scope_name(directory))
            .flatten()
            .map_or_else(|| self.value.clone(), |scope| format!("{}-{scope}", self.value))
    }
}

fn expand(template: &str, service: &str, directory: &Path) -> Expanded {
    if !template.contains('{') {
        return Expanded { value: template.to_owned(), used_branch: false, used_service: false };
    }
    let mut value = String::with_capacity(template.len());
    let mut used_branch = false;
    let mut used_service = false;
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        value.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}').map(|index| open + index) else {
            break;
        };
        let key = &rest[open + 1..close];
        match placeholder(key, service, directory) {
            Some(replacement) => {
                used_branch |= key == "branch";
                used_service |= key == "service";
                value.push_str(&replacement);
            }
            // Unknown placeholders stay literal so the mistake is visible in the URL.
            None => value.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    value.push_str(rest);
    Expanded { value, used_branch, used_service }
}

fn placeholder(key: &str, service: &str, directory: &Path) -> Option<String> {
    if !PLACEHOLDERS.contains(&key) {
        return None;
    }
    let value = match key {
        "repo" => project_root::repo_name(directory).unwrap_or_default(),
        "branch" => project_root::branch(directory).unwrap_or_default(),
        "service" => service.to_owned(),
        "dir" => {
            directory.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned()
        }
        _ => project_root::worktree_name(directory).unwrap_or_default(),
    };
    Some(value)
}

fn with_branch(base: &str, directory: &Path) -> String {
    let base = sanitize(base);
    match project_root::branch(directory) {
        Some(branch) if !project_root::is_default_branch(directory, &branch) => {
            match sanitize(&branch) {
                branch if branch.is_empty() => base,
                branch => format!("{base}-{branch}"),
            }
        }
        _ => base,
    }
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
    let path = project_root::config_path(directory)?;
    let value = fs::read_to_string(path).ok()?;
    // `toml::Value` parses a bare value, not a document; a table is required to read a key.
    toml::from_str::<toml::Table>(&value).ok()?.get("name")?.as_str().map(str::to_owned)
}

fn package_name(directory: &Path) -> Option<String> {
    let value = fs::read(directory.join("package.json")).ok()?;
    serde_json::from_slice::<serde_json::Value>(&value)
        .ok()?
        .get("name")?
        .as_str()
        .map(str::to_owned)
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
