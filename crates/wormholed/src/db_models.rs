//! Serializable records stored by the relay database.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::buffer::BufferedRequest;
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, Persistence};

/// Sanitized persistent bind configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PersistedBindSpec {
    /// HTTP bind without raw edge-auth credentials.
    Http {
        host: Option<String>,
        domain: Option<String>,
        persist: Persistence,
        buffer: Option<BufferPolicy>,
    },
    /// TCP bind.
    Tcp { remote_port: Option<u16>, persist: Persistence },
}

/// Stored public endpoint allocated to a bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PersistedEndpoint {
    /// Fully qualified public hostname.
    Hostname(String),
    /// Public TCP port.
    TcpPort(u16),
}

/// Derived edge-auth verification material; never returned by list/admin APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifier {
    /// Argon2id password verifier including parameters and salt.
    pub basic_argon2: Option<String>,
    /// SHA-256 bearer-token digest in padded base64.
    pub bearer_sha256: Option<String>,
    /// HMAC key required to verify expiring share links.
    pub link_hmac_key: Option<String>,
}

/// Durable reservation for a persistent bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedBind {
    /// Secret token used to reclaim this reservation.
    pub reservation: Uuid,
    /// Sanitized bind request.
    pub spec: PersistedBindSpec,
    /// Derived access-control material.
    pub auth_verifier: Option<AuthVerifier>,
    /// Stable server-decided hostname or TCP port.
    pub endpoint: PersistedEndpoint,
    /// Owning key fingerprint.
    pub key_fpr: String,
    /// Creation instant.
    pub created: Timestamp,
    /// Most recent owner activity.
    pub last_seen: Timestamp,
}

/// Authorized client key record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedKey {
    /// Canonical padded base64 public key.
    pub pub_b64: String,
    /// Operator-provided display name.
    pub name: String,
    /// Authorization instant.
    pub created: Timestamp,
    /// Revocation tombstone.
    pub revoked: bool,
}

/// Hashed server-issued client enrollment credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentInvite {
    /// Stable public identifier used for listing and revocation.
    pub id: String,
    /// SHA-256 digest of the secret token component.
    pub secret_sha256: String,
    /// Display name assigned to keys enrolled with this invite.
    pub name: String,
    /// Creation time as a Unix timestamp.
    pub created_at: i64,
    /// Optional expiry as a Unix timestamp.
    pub expires_at: Option<i64>,
    /// Optional maximum successful enrollment count.
    pub max_uses: Option<u32>,
    /// Successful enrollment count.
    pub uses: u32,
    /// Durable revocation tombstone.
    pub revoked: bool,
}

/// Durable failed webhook payload used by Stage 07.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedWebhook {
    /// Original buffered request.
    pub request: BufferedRequest,
    /// Final delivery failure.
    pub reason: String,
    /// Failure instant.
    pub failed_at: Timestamp,
}
