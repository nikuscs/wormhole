//! Authorized-key import, management, and fail-closed policy decisions.

use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

use camino::{Utf8Path, Utf8PathBuf};
use jiff::Timestamp;
use wormhole_proto::PublicKeyRef;

use crate::{
    config::LimitsConfig,
    db::{AuthorizedKey, DbError, RelayDb},
};

/// Per-key limits returned with an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLimits {
    /// Global simultaneous bind limit.
    pub max_binds: u32,
    /// Global simultaneous session limit.
    pub max_sessions: u32,
    /// Per-session simultaneous stream limit.
    pub max_streams: u32,
}

impl From<&LimitsConfig> for KeyLimits {
    fn from(value: &LimitsConfig) -> Self {
        Self {
            max_binds: value.max_binds_per_key,
            max_sessions: value.max_sessions_per_key,
            max_streams: value.max_streams_per_session,
        }
    }
}

/// Result of looking up a presented public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDecision {
    /// Key is authorized with its operator name and limits.
    Allowed { name: String, fingerprint: String, limits: KeyLimits },
    /// A durable revocation tombstone exists.
    Revoked,
    /// No authoritative database row exists.
    Unknown,
}

/// redb-backed authorized-key policy.
pub struct AuthStore {
    database: Arc<RelayDb>,
    limits: KeyLimits,
}

impl AuthStore {
    /// Creates a policy store backed by the authoritative relay database.
    pub const fn new(database: Arc<RelayDb>, limits: KeyLimits) -> Self {
        Self { database, limits }
    }

    /// Imports previously unseen entries from `*.pub` files.
    pub fn import_directory(&self, directory: &Utf8Path) -> Result<usize, AuthzError> {
        fs::create_dir_all(directory)
            .map_err(|source| AuthzError::Io { path: directory.to_owned(), source })?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|source| AuthzError::Io { path: directory.to_owned(), source })?;
        let mut imported = 0;
        for entry in fs::read_dir(directory)
            .map_err(|source| AuthzError::Io { path: directory.to_owned(), source })?
        {
            let entry =
                entry.map_err(|source| AuthzError::Io { path: directory.to_owned(), source })?;
            let path = Utf8PathBuf::from_path_buf(entry.path()).map_err(|path| {
                AuthzError::Invalid(format!("authorized-key path is not UTF-8: {}", path.display()))
            })?;
            if path.extension() != Some("pub") || !path.is_file() {
                continue;
            }
            imported += self.import_file(&path)?;
        }
        Ok(imported)
    }

    /// Authorizes or re-authorizes a canonical public key under an operator name.
    pub fn authorize(&self, public_key: &str, name: &str) -> Result<String, AuthzError> {
        if name.trim().is_empty() {
            return Err(AuthzError::Invalid("key name must not be empty".to_owned()));
        }
        let key = PublicKeyRef::parse(public_key)?;
        let fingerprint = key.fingerprint();
        self.database.put_key(
            &fingerprint,
            &AuthorizedKey {
                pub_b64: key.as_base64().to_owned(),
                name: name.trim().to_owned(),
                created: Timestamp::now(),
                revoked: false,
            },
        )?;
        Ok(fingerprint)
    }

    /// Writes a durable revocation tombstone for an existing key.
    pub fn revoke(&self, fingerprint: &str) -> Result<(), AuthzError> {
        let mut key = self
            .database
            .get_key(fingerprint)?
            .ok_or_else(|| AuthzError::UnknownFingerprint(fingerprint.to_owned()))?;
        key.revoked = true;
        self.database.put_key(fingerprint, &key)?;
        Ok(())
    }

    /// Lists authoritative key rows, including revoked tombstones.
    pub fn list(&self) -> Result<Vec<(String, AuthorizedKey)>, AuthzError> {
        Ok(self.database.list_keys()?)
    }

    /// Resolves one presented public key against authoritative redb state.
    pub fn is_authorized(&self, public_key: &str) -> Result<KeyDecision, AuthzError> {
        let Ok(key) = PublicKeyRef::parse(public_key) else {
            return Ok(KeyDecision::Unknown);
        };
        let fingerprint = key.fingerprint();
        let Some(stored) = self.database.get_key(&fingerprint)? else {
            return Ok(KeyDecision::Unknown);
        };
        if stored.pub_b64 != key.as_base64() {
            return Ok(KeyDecision::Unknown);
        }
        if stored.revoked {
            return Ok(KeyDecision::Revoked);
        }
        Ok(KeyDecision::Allowed { name: stored.name, fingerprint, limits: self.limits })
    }

    fn import_file(&self, path: &Utf8Path) -> Result<usize, AuthzError> {
        let contents = fs::read_to_string(path)
            .map_err(|source| AuthzError::Io { path: path.to_owned(), source })?;
        let fallback_name = path.file_stem().unwrap_or("imported");
        let mut imported = 0;
        for line in contents.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = PublicKeyRef::parse(line)?;
            let fingerprint = key.fingerprint();
            if self.database.get_key(&fingerprint)?.is_some() {
                continue;
            }
            self.database.put_key(
                &fingerprint,
                &AuthorizedKey {
                    pub_b64: key.as_base64().to_owned(),
                    name: key.comment().unwrap_or(fallback_name).to_owned(),
                    created: Timestamp::now(),
                    revoked: false,
                },
            )?;
            imported += 1;
        }
        Ok(imported)
    }
}

/// Authorized-key storage or parsing failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    /// Database operation failed.
    #[error(transparent)]
    Database(#[from] DbError),
    /// Public-key parsing failed.
    #[error(transparent)]
    Protocol(#[from] wormhole_proto::ProtoError),
    /// Authorized-key file I/O failed.
    #[error("authorized-key I/O failed for {path}: {source}")]
    Io { path: Utf8PathBuf, source: std::io::Error },
    /// Input failed semantic validation.
    #[error("invalid authorized key: {0}")]
    Invalid(String),
    /// Revocation targeted an unknown fingerprint.
    #[error("unknown key fingerprint: {0}")]
    UnknownFingerprint(String),
}

#[cfg(test)]
#[path = "authz_tests.rs"]
mod tests;
