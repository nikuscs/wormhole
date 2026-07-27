//! Layered global, project, and explicit client configuration.

use std::{collections::BTreeMap, env, fs};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::{error::ConfigError, remotes::Remote};

/// Effective client configuration after layer merging.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Default named Wormhole remote.
    pub default_remote: Option<String>,
    /// Named relay definitions.
    pub remotes: BTreeMap<String, Remote>,
    /// User-defined interface aliases.
    pub aliases: BTreeMap<String, String>,
    /// Endpoint defaults.
    pub defaults: ClientDefaults,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

/// Defaults used when a service omits endpoint details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientDefaults {
    /// Driver names to instantiate.
    pub drivers: Vec<String>,
    /// Whether request inspection defaults on.
    pub inspect: bool,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

impl Default for ClientDefaults {
    fn default() -> Self {
        Self { drivers: vec!["wormhole".to_owned()], inspect: false, extra: BTreeMap::new() }
    }
}

/// Sparse explicit override layer supplied by Stage 05.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigLayer {
    /// Optional default remote override.
    pub default_remote: Option<String>,
    /// Remote additions or replacements.
    #[serde(default)]
    pub remotes: BTreeMap<String, Remote>,
    /// Alias additions or replacements.
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    /// Sparse defaults override.
    pub defaults: Option<DefaultsLayer>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

/// Sparse endpoint-default override.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DefaultsLayer {
    /// Optional driver list replacement.
    pub drivers: Option<Vec<String>>,
    /// Optional inspection default replacement.
    pub inspect: Option<bool>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

impl ClientConfig {
    /// Loads built-ins, global config, an optional project file, then explicit overrides.
    pub fn load(project: Option<&Utf8Path>, explicit: ConfigLayer) -> Result<Self, ConfigError> {
        let global = global_config_path()?;
        Self::load_from_paths(Some(&global), project, explicit)
    }

    /// Loads explicit paths; exposed for deterministic tests and embedders.
    pub fn load_from_paths(
        global: Option<&Utf8Path>,
        project: Option<&Utf8Path>,
        explicit: ConfigLayer,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(layer) = read_optional_layer(global)? {
            merge(&mut config, layer);
        }
        if let Some(layer) = read_optional_layer(project)? {
            merge(&mut config, layer);
        }
        warn_unknowns("explicit", &explicit);
        merge(&mut config, explicit);
        config.validate()?;
        Ok(config)
    }

    /// Validates references and security-sensitive names.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(default) = &self.default_remote
            && !self.remotes.contains_key(default)
        {
            return Err(ConfigError::Invalid(format!("unknown default_remote: {default}")));
        }
        for (name, remote) in &self.remotes {
            if name.trim().is_empty() || remote.server_name.trim().is_empty() {
                return Err(ConfigError::Invalid("remote names must not be empty".to_owned()));
            }
            let valid_addr = remote.addr.rsplit_once(':').is_some_and(|(host, port)| {
                let host_valid = !host.is_empty()
                    && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']')));
                host_valid && port.parse::<u16>().is_ok_and(|port| port != 0)
            });
            if !valid_addr {
                return Err(ConfigError::Invalid(format!(
                    "remote {name} addr must include a non-zero UDP port"
                )));
            }
        }
        if self.defaults.drivers.is_empty() {
            return Err(ConfigError::Invalid("defaults.drivers must not be empty".to_owned()));
        }
        Ok(())
    }
}

/// Returns `WORMHOLE_CONFIG` or `~/.config/wormhole/config.toml`.
pub fn global_config_path() -> Result<Utf8PathBuf, ConfigError> {
    if let Some(path) = env::var_os("WORMHOLE_CONFIG") {
        return Utf8PathBuf::from_path_buf(path.into()).map_err(|path| {
            ConfigError::Invalid(format!("WORMHOLE_CONFIG is not UTF-8: {}", path.display()))
        });
    }
    let base = directories::BaseDirs::new()
        .ok_or_else(|| ConfigError::Invalid("home directory is unavailable".to_owned()))?;
    Utf8PathBuf::from_path_buf(base.home_dir().join(".config/wormhole/config.toml")).map_err(
        |path| ConfigError::Invalid(format!("config path is not UTF-8: {}", path.display())),
    )
}

fn read_optional_layer(path: Option<&Utf8Path>) -> Result<Option<ConfigLayer>, ConfigError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .map_err(|source| ConfigError::Io { path: path.to_owned(), source })?;
    let layer = toml::from_str::<ConfigLayer>(&contents)
        .map_err(|source| ConfigError::Toml { path: path.to_owned(), source })?;
    warn_unknowns(path.as_str(), &layer);
    Ok(Some(layer))
}

fn merge(config: &mut ClientConfig, layer: ConfigLayer) {
    if layer.default_remote.is_some() {
        config.default_remote = layer.default_remote;
    }
    config.remotes.extend(layer.remotes);
    config.aliases.extend(layer.aliases);
    if let Some(defaults) = layer.defaults {
        if let Some(drivers) = defaults.drivers {
            config.defaults.drivers = drivers;
        }
        if let Some(inspect) = defaults.inspect {
            config.defaults.inspect = inspect;
        }
    }
    config.extra.extend(layer.extra);
}

fn warn_unknowns(source: &str, layer: &ConfigLayer) {
    for key in layer.extra.keys() {
        tracing::warn!(%source, %key, "unknown client configuration key");
    }
    for (name, remote) in &layer.remotes {
        for key in remote.extra.keys() {
            tracing::warn!(%source, remote = %name, %key, "unknown remote configuration key");
        }
    }
    if let Some(defaults) = &layer.defaults {
        for key in defaults.extra.keys() {
            tracing::warn!(%source, %key, "unknown defaults configuration key");
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
