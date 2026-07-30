//! Authorized-key import, management, and fail-closed policy decisions.

use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use camino::{Utf8Path, Utf8PathBuf};
use jiff::Timestamp;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use wormhole_proto::PublicKeyRef;

use crate::{
    config::LimitsConfig,
    db::{AuthorizedKey, DbError, EnrollmentInvite, RelayDb},
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

/// Newly generated invite; the plaintext token is returned exactly once.
pub struct CreatedInvite {
    pub id: String,
    pub token: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u32>,
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

    /// Creates a hashed enrollment invite and returns its one-time plaintext representation.
    pub fn create_invite(
        &self,
        name: &str,
        ttl_secs: Option<u64>,
        max_uses: Option<u32>,
    ) -> Result<CreatedInvite, AuthzError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(AuthzError::Invalid(
                "invite name must contain 1-128 characters".to_owned(),
            ));
        }
        if max_uses == Some(0) {
            return Err(AuthzError::Invalid("invite uses must be greater than zero".to_owned()));
        }
        let now = Timestamp::now().as_second();
        let expires_at = ttl_secs
            .map(|ttl| {
                i64::try_from(ttl)
                    .ok()
                    .and_then(|ttl| now.checked_add(ttl))
                    .ok_or_else(|| AuthzError::Invalid("invite TTL is too large".to_owned()))
            })
            .transpose()?;
        for _attempt in 0..8 {
            let mut id_bytes = [0_u8; 9];
            let mut secret_bytes = [0_u8; 32];
            rand::rng().fill(&mut id_bytes);
            rand::rng().fill(&mut secret_bytes);
            let id = URL_SAFE_NO_PAD.encode(id_bytes);
            let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
            let secret_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
            let invite = EnrollmentInvite {
                id: id.clone(),
                secret_sha256,
                name: name.to_owned(),
                created_at: now,
                expires_at,
                max_uses,
                uses: 0,
                revoked: false,
            };
            if self.database.put_invite(&invite)? {
                return Ok(CreatedInvite {
                    id: id.clone(),
                    token: format!("whi_{id}_{secret}"),
                    name: name.to_owned(),
                    created_at: now,
                    expires_at,
                    max_uses,
                });
            }
        }
        Err(AuthzError::Invalid("could not allocate a unique invite identifier".to_owned()))
    }

    /// Lists invite metadata without plaintext secrets or secret digests.
    pub fn list_invites(&self) -> Result<Vec<EnrollmentInvite>, AuthzError> {
        Ok(self.database.list_invites()?)
    }

    /// Durably revokes an invite by its public identifier.
    pub fn revoke_invite(&self, id: &str) -> Result<(), AuthzError> {
        if !self.database.revoke_invite(id)? {
            return Err(AuthzError::UnknownInvite(id.to_owned()));
        }
        Ok(())
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

    /// Resolves a key and optionally consumes an invite to authorize an unknown key.
    pub fn authorize_or_redeem(
        &self,
        public_key: &str,
        invite: Option<&str>,
    ) -> Result<KeyDecision, AuthzError> {
        self.authorize_or_redeem_at(public_key, invite, Timestamp::now().as_second())
    }

    fn authorize_or_redeem_at(
        &self,
        public_key: &str,
        invite: Option<&str>,
        now: i64,
    ) -> Result<KeyDecision, AuthzError> {
        let decision = self.is_authorized(public_key)?;
        if !matches!(decision, KeyDecision::Unknown) {
            return Ok(decision);
        }
        let Some(invite) = invite else {
            return Ok(KeyDecision::Unknown);
        };
        let Ok(key) = PublicKeyRef::parse(public_key) else {
            return Ok(KeyDecision::Unknown);
        };
        let Some((id, secret)) = parse_invite_token(invite) else {
            return Ok(KeyDecision::Unknown);
        };
        let secret_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        let fingerprint = key.fingerprint();
        if !self.database.redeem_invite(id, &secret_sha256, now, &fingerprint, key.as_base64())? {
            return Ok(KeyDecision::Unknown);
        }
        self.is_authorized(public_key)
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
    /// Revocation targeted an unknown invite identifier.
    #[error("unknown invite: {0}")]
    UnknownInvite(String),
}

fn parse_invite_token(token: &str) -> Option<(&str, &str)> {
    let encoded = token.strip_prefix("whi_")?;
    if !encoded.is_ascii() || encoded.len() != 56 || encoded.as_bytes()[12] != b'_' {
        return None;
    }
    let id = &encoded[..12];
    let secret = &encoded[13..];
    let id_bytes = URL_SAFE_NO_PAD.decode(id).ok()?;
    let secret_bytes = URL_SAFE_NO_PAD.decode(secret).ok()?;
    (id_bytes.len() == 9 && secret_bytes.len() == 32).then_some((id, secret))
}

#[cfg(test)]
#[path = "authz_tests.rs"]
mod tests;
