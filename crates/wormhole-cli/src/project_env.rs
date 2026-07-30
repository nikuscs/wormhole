//! Project-local environment overrides used by tunnel commands.

use std::path::Path;

use crate::error::CliError;

pub fn config_path(directory: &Path) -> Result<Option<camino::Utf8PathBuf>, CliError> {
    let path = directory.join("wormhole.toml");
    if !path.exists() {
        return Ok(None);
    }
    camino::Utf8PathBuf::from_path_buf(path)
        .map(Some)
        .map_err(|_| CliError::Invalid("project path is not UTF-8".to_owned()))
}

pub fn domain_override(directory: &Path) -> Result<Option<String>, CliError> {
    if let Some(value) = std::env::var_os("WORMHOLE_DOMAIN") {
        return value
            .into_string()
            .map(Some)
            .map_err(|_| CliError::Invalid("WORMHOLE_DOMAIN is not UTF-8".to_owned()));
    }
    let path = directory.join(".env");
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(parse_domain(&contents))
}

fn parse_domain(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line.split_once('=')?;
        (key.trim() == "WORMHOLE_DOMAIN").then(|| value.trim().trim_matches(['\'', '"']).to_owned())
    })
}

#[cfg(test)]
#[path = "project_env_tests.rs"]
mod tests;
