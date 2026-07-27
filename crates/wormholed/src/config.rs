//! Relay configuration loading, defaults, initialization, and validation.

use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

/// Complete `wormholed.toml` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WormholedConfig {
    /// Public listener and domain settings.
    pub server: ServerConfig,
    /// Certificate source and per-mode settings.
    pub tls: TlsConfig,
    /// Public TCP-forward range.
    pub tcp: TcpConfig,
    /// Global relay limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Authorized-key import path.
    pub auth: AuthConfig,
}

/// Public listener and domain settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server-controlled public domains, default first.
    pub domains: Vec<String>,
    /// Optional public HTTPS port when NAT differs from the bound port.
    pub public_https_port: Option<u16>,
    /// QUIC UDP listener.
    pub quic_addr: SocketAddr,
    /// HTTPS TCP listener.
    pub https_addr: SocketAddr,
    /// HTTP redirect listener.
    pub http_addr: SocketAddr,
    /// Persistent state and certificate directory.
    pub data_dir: Utf8PathBuf,
}

/// TLS certificate mode and mode-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate provisioning mode.
    pub mode: TlsMode,
    /// Static wildcard certificate mappings.
    #[serde(rename = "static")]
    pub static_config: Option<StaticTlsConfig>,
    /// Built-in ACME DNS-01 settings.
    pub acme: Option<AcmeConfig>,
}

/// Supported certificate provisioning modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Operator-managed wildcard PEM files.
    Static,
    /// Built-in wildcard issuance using ACME DNS-01.
    AcmeDns01,
    /// Ephemeral development certificates.
    SelfSigned,
}

/// Static wildcard certificate list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticTlsConfig {
    /// One certificate mapping per configured domain.
    pub certs: Vec<StaticCertificate>,
}

/// One static wildcard certificate mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCertificate {
    /// Configured relay domain covered by this certificate.
    pub domain: String,
    /// PEM certificate chain path.
    pub cert: Utf8PathBuf,
    /// PEM private key path.
    pub key: Utf8PathBuf,
}

/// ACME DNS-01 and Cloudflare settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// ACME account contact URI.
    pub contact: String,
    /// ACME directory URL.
    pub directory: String,
    /// DNS provider identifier; currently `cloudflare` only.
    pub dns_provider: String,
    /// File containing a Cloudflare API token.
    pub cloudflare_token_file: Utf8PathBuf,
}

/// TCP forward allocation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    /// Inclusive public port range.
    pub port_range: PortRange,
}

/// Inclusive TCP port range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortRange {
    /// First available port.
    pub start: u16,
    /// Last available port.
    pub end: u16,
}

/// Global relay safety limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum binds across all sessions for one key.
    pub max_binds_per_key: u32,
    /// Maximum simultaneous sessions for one key.
    pub max_sessions_per_key: u32,
    /// Maximum streams in one session.
    pub max_streams_per_session: u32,
    /// Maximum handshakes accepted from one IP per minute.
    pub handshake_per_ip_per_min: u32,
    /// Maximum buffered bytes retained for one key.
    pub buffer_max_bytes_per_key: String,
    /// Maximum buffered bytes retained across the relay.
    pub buffer_max_bytes_total: String,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_binds_per_key: 32,
            max_sessions_per_key: 8,
            max_streams_per_session: 1024,
            handshake_per_ip_per_min: 30,
            buffer_max_bytes_per_key: "100MiB".to_owned(),
            buffer_max_bytes_total: "1GiB".to_owned(),
        }
    }
}

/// Authorized-key import settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Directory containing import-only `*.pub` files.
    pub authorized_keys: Utf8PathBuf,
}

impl WormholedConfig {
    /// Loads and parses TOML from disk.
    pub fn load(path: &Utf8Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_owned(), source })?;
        toml::from_str(&contents)
            .map_err(|source| ConfigError::Parse { path: path.to_owned(), source })
    }

    /// Validates all cross-field and filesystem invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_domains(&self.server.domains)?;
        if self.server.public_https_port == Some(0) {
            return Err(ConfigError::Invalid(
                "server.public_https_port must be non-zero when set".to_owned(),
            ));
        }
        if self.tcp.port_range.start == 0 || self.tcp.port_range.start > self.tcp.port_range.end {
            return Err(ConfigError::Invalid(
                "tcp.port_range must be non-zero and ordered".to_owned(),
            ));
        }
        validate_nonzero_limits(&self.limits)?;
        parse_byte_size(&self.limits.buffer_max_bytes_per_key)?;
        parse_byte_size(&self.limits.buffer_max_bytes_total)?;
        match self.tls.mode {
            TlsMode::Static => validate_static_tls(self)?,
            TlsMode::AcmeDns01 => validate_acme(self)?,
            TlsMode::SelfSigned => {}
        }
        if self.auth.authorized_keys.exists() && !self.auth.authorized_keys.is_dir() {
            return Err(ConfigError::Invalid(format!(
                "auth.authorized_keys is not a directory: {}",
                self.auth.authorized_keys
            )));
        }
        Ok(())
    }

    /// Writes a development-safe commented config and creates its state directories.
    pub fn initialize(path: &Utf8Path) -> Result<(), ConfigError> {
        if path.exists() {
            return Err(ConfigError::Invalid(format!(
                "refusing to overwrite existing config: {path}"
            )));
        }
        let parent = path.parent().unwrap_or_else(|| Utf8Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|source| ConfigError::Write { path: parent.to_owned(), source })?;
        let data_dir = path.with_extension("data");
        let authorized_keys = data_dir.join("authorized_keys");
        fs::create_dir_all(&authorized_keys)
            .map_err(|source| ConfigError::Write { path: authorized_keys.clone(), source })?;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
            .map_err(|source| ConfigError::Write { path: data_dir.clone(), source })?;
        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o700))
            .map_err(|source| ConfigError::Write { path: authorized_keys.clone(), source })?;
        let config = Self::development(data_dir, authorized_keys);
        let serialized = toml::to_string_pretty(&config)?;
        let contents = format!(
            "# Wormhole relay configuration. Replace the development domain before production.\n\
             # Static and ACME wildcard certificate examples are documented in docs/server-setup.md.\n{serialized}"
        );
        fs::write(path, contents)
            .map_err(|source| ConfigError::Write { path: path.to_owned(), source })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|source| ConfigError::Write { path: path.to_owned(), source })
    }

    fn development(data_dir: Utf8PathBuf, authorized_keys: Utf8PathBuf) -> Self {
        Self {
            server: ServerConfig {
                domains: vec!["localtest.wormhole".to_owned()],
                public_https_port: None,
                quic_addr: "127.0.0.1:443".parse().expect("valid default address"),
                https_addr: "127.0.0.1:443".parse().expect("valid default address"),
                http_addr: "127.0.0.1:80".parse().expect("valid default address"),
                data_dir,
            },
            tls: TlsConfig { mode: TlsMode::SelfSigned, static_config: None, acme: None },
            tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 20_000 } },
            limits: LimitsConfig::default(),
            auth: AuthConfig { authorized_keys },
        }
    }
}

fn validate_domains(domains: &[String]) -> Result<(), ConfigError> {
    if domains.is_empty() {
        return Err(ConfigError::Invalid("server.domains must not be empty".to_owned()));
    }
    let mut unique = HashSet::new();
    for domain in domains {
        if !is_dns_name(domain) {
            return Err(ConfigError::Invalid(format!("invalid server domain: {domain}")));
        }
        if !unique.insert(domain) {
            return Err(ConfigError::Invalid(format!("duplicate server domain: {domain}")));
        }
    }
    Ok(())
}

fn is_dns_name(domain: &str) -> bool {
    if domain.len() > 253 || domain.contains(|character: char| character.is_ascii_uppercase()) {
        return false;
    }
    let mut labels = domain.split('.');
    let valid = labels.all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
    });
    valid && domain.contains('.')
}

fn validate_nonzero_limits(limits: &LimitsConfig) -> Result<(), ConfigError> {
    if limits.max_binds_per_key == 0
        || limits.max_sessions_per_key == 0
        || limits.max_streams_per_session == 0
        || limits.handshake_per_ip_per_min == 0
    {
        return Err(ConfigError::Invalid("all numeric limits must be non-zero".to_owned()));
    }
    Ok(())
}

fn validate_static_tls(config: &WormholedConfig) -> Result<(), ConfigError> {
    let static_config =
        config.tls.static_config.as_ref().ok_or_else(|| {
            ConfigError::Invalid("tls.static is required in static mode".to_owned())
        })?;
    for domain in &config.server.domains {
        let certificate =
            static_config.certs.iter().find(|candidate| candidate.domain == *domain).ok_or_else(
                || ConfigError::Invalid(format!("missing static certificate for {domain}")),
            )?;
        require_file(&certificate.cert, "certificate")?;
        require_file(&certificate.key, "private key")?;
    }
    Ok(())
}

fn validate_acme(config: &WormholedConfig) -> Result<(), ConfigError> {
    let acme = config.tls.acme.as_ref().ok_or_else(|| {
        ConfigError::Invalid("tls.acme is required in acme-dns01 mode".to_owned())
    })?;
    if acme.dns_provider != "cloudflare" {
        return Err(ConfigError::Invalid("tls.acme.dns_provider must be cloudflare".to_owned()));
    }
    if !acme.contact.starts_with("mailto:") || !acme.directory.starts_with("https://") {
        return Err(ConfigError::Invalid("invalid ACME contact or directory URL".to_owned()));
    }
    require_file(&acme.cloudflare_token_file, "Cloudflare token")?;
    let mode = fs::metadata(&acme.cloudflare_token_file)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?
        .mode()
        & 0o777;
    if mode & 0o400 == 0 || mode & 0o077 != 0 {
        return Err(ConfigError::Invalid(format!(
            "Cloudflare token must be owner-readable with no group/other access, got {mode:04o}"
        )));
    }
    Ok(())
}

fn require_file(path: &Utf8Path, kind: &str) -> Result<(), ConfigError> {
    if !path.is_file() {
        return Err(ConfigError::Invalid(format!("{kind} file does not exist: {path}")));
    }
    Ok(())
}

pub fn parse_byte_size(value: &str) -> Result<u64, ConfigError> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("MiB") {
        (number, 1024_u64.pow(2))
    } else if let Some(number) = value.strip_suffix("GiB") {
        (number, 1024_u64.pow(3))
    } else {
        return Err(ConfigError::Invalid(format!("invalid byte size: {value}")));
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid(format!("invalid byte size: {value}")))?;
    number
        .checked_mul(multiplier)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| ConfigError::Invalid(format!("invalid byte size: {value}")))
}

/// Configuration load, parse, initialization, or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read a config file.
    #[error("failed to read {path}: {source}")]
    Read { path: Utf8PathBuf, source: std::io::Error },
    /// TOML parsing failed.
    #[error("failed to parse {path}: {source}")]
    Parse { path: Utf8PathBuf, source: toml::de::Error },
    /// TOML serialization failed.
    #[error("failed to serialize default config: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Failed to create a config or state directory.
    #[error("failed to write {path}: {source}")]
    Write { path: Utf8PathBuf, source: std::io::Error },
    /// A semantic validation rule failed.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
