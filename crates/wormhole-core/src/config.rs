//! Layered global, project, and explicit client configuration.

use std::{collections::BTreeMap, env, fs};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::{error::ConfigError, model::RetryPolicy, remotes::Remote};

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
    /// Default local HTTP delivery retry policy.
    pub retry: Option<RetryPolicy>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

impl Default for ClientDefaults {
    fn default() -> Self {
        Self {
            drivers: vec!["wormhole".to_owned()],
            inspect: false,
            retry: None,
            extra: BTreeMap::new(),
        }
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
    /// Optional delivery retry default replacement.
    #[serde(default, deserialize_with = "deserialize_retry_policy")]
    pub retry: Option<RetryPolicy>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    extra: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct RetryConfig {
    attempts: u32,
    backoff: String,
    max_backoff: Option<String>,
    #[serde(default)]
    on: Vec<String>,
    max_body: Option<String>,
    total_deadline: Option<String>,
}

fn deserialize_retry_policy<'de, D>(deserializer: D) -> Result<Option<RetryPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(config) = Option::<RetryConfig>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let duration = |value: &str| {
        humantime::parse_duration(value)
            .map_err(serde::de::Error::custom)?
            .as_millis()
            .try_into()
            .map_err(serde::de::Error::custom)
    };
    Ok(Some(RetryPolicy {
        max_attempts: config.attempts,
        initial_delay_ms: duration(&config.backoff)?,
        max_delay_ms: config.max_backoff.as_deref().map(duration).transpose()?.unwrap_or(30_000),
        retry_connect: config.on.is_empty() || config.on.iter().any(|item| item == "connect-error"),
        retry_5xx: config.on.iter().any(|item| item == "5xx"),
        max_body_bytes: config
            .max_body
            .as_deref()
            .map(parse_retry_bytes)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or(1024 * 1024),
        total_deadline_ms: config
            .total_deadline
            .as_deref()
            .map(duration)
            .transpose()?
            .unwrap_or(60_000),
    }))
}

fn parse_retry_bytes(value: &str) -> Result<u64, String> {
    let split = value.find(|character: char| !character.is_ascii_digit()).unwrap_or(value.len());
    let number = value[..split].parse::<u64>().map_err(|error| error.to_string())?;
    let multiplier = match value[split..].trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        unit => return Err(format!("unsupported retry body unit: {unit}")),
    };
    number.checked_mul(multiplier).ok_or_else(|| "retry body size overflow".to_owned())
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
        if let Some(layer) = read_optional_layer(global, false)? {
            merge(&mut config, layer);
        }
        if let Some(layer) = read_optional_layer(project, true)? {
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
            if !valid_authority(&remote.addr) {
                return Err(ConfigError::Invalid(format!(
                    "remote {name} addr must include a non-zero UDP port"
                )));
            }
            if remote.https_addr.as_deref().is_some_and(|address| !valid_authority(address)) {
                return Err(ConfigError::Invalid(format!(
                    "remote {name} https_addr must include a non-zero TCP port"
                )));
            }
        }
        if self.defaults.drivers.is_empty() {
            return Err(ConfigError::Invalid("defaults.drivers must not be empty".to_owned()));
        }
        Ok(())
    }
}

fn valid_authority(address: &str) -> bool {
    address.rsplit_once(':').is_some_and(|(host, port)| {
        let host_valid = !host.is_empty()
            && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']')));
        host_valid && port.parse::<u16>().is_ok_and(|port| port != 0)
    })
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

fn read_optional_layer(
    path: Option<&Utf8Path>,
    project: bool,
) -> Result<Option<ConfigLayer>, ConfigError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .map_err(|source| ConfigError::Io { path: path.to_owned(), source })?;
    let mut layer = toml::from_str::<ConfigLayer>(&contents)
        .map_err(|source| ConfigError::Toml { path: path.to_owned(), source })?;
    if project {
        layer.extra.remove("name");
        layer.extra.remove("service");
    }
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
        if defaults.retry.is_some() {
            config.defaults.retry = defaults.retry;
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
