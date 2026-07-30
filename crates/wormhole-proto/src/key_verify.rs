//! Portable Ed25519 public-key parsing and challenge verification.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::error::ProtoError;

const CHALLENGE_CONTEXT: &[u8] = b"wormhole-v1-challenge";
pub const KEY_BYTES: usize = 32;

/// A validated authorized-keys entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRef {
    encoded: String,
    comment: Option<String>,
}

impl PublicKeyRef {
    /// Parses `<padded-public-key-base64> <optional comment>`.
    pub fn parse(line: &str) -> Result<Self, ProtoError> {
        let line = line.trim();
        let split_at = line.find(char::is_whitespace).unwrap_or(line.len());
        let (encoded, remainder) = line.split_at(split_at);
        decode_verifying_key(encoded)?;
        let comment =
            if remainder.trim().is_empty() { None } else { Some(remainder.trim().to_owned()) };
        Ok(Self { encoded: encoded.to_owned(), comment })
    }

    /// Returns the padded base64 public key.
    pub fn as_base64(&self) -> &str {
        &self.encoded
    }

    /// Returns the optional administrator comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Returns the stable SHA-256 public-key fingerprint.
    pub fn fingerprint(&self) -> String {
        let verifying = decode_verifying_key(&self.encoded).expect("validated public key");
        fingerprint_bytes(verifying.as_bytes())
    }
}

/// Verifies a canonical relay challenge signature using strict Ed25519 validation.
pub fn verify_challenge(
    public_base64: &str,
    nonce: &[u8; KEY_BYTES],
    server: &str,
    proto: u16,
    signature_base64: &str,
) -> bool {
    let Ok(verifying) = decode_verifying_key(public_base64) else {
        return false;
    };
    let Ok(signature_bytes) = decode_array::<64>(signature_base64) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying.verify_strict(&challenge_transcript(nonce, server, proto), &signature).is_ok()
}

pub fn challenge_transcript(nonce: &[u8; KEY_BYTES], server: &str, proto: u16) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(CHALLENGE_CONTEXT.len() + nonce.len() + server.len() + 10);
    transcript.extend_from_slice(CHALLENGE_CONTEXT);
    append_length_prefixed(&mut transcript, nonce);
    append_length_prefixed(&mut transcript, server.as_bytes());
    transcript.extend_from_slice(&proto.to_le_bytes());
    transcript
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("challenge component length fits u32");
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
}

pub fn fingerprint_bytes(public: &[u8; KEY_BYTES]) -> String {
    format!("WH256:{}", STANDARD.encode(Sha256::digest(public)))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn decode_nonce(encoded: &str) -> Result<[u8; KEY_BYTES], ProtoError> {
    decode_array(encoded)
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, ProtoError> {
    let public = decode_array(encoded)?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|error| ProtoError::InvalidIdentity(format!("invalid public key: {error}")))?;
    if verifying.is_weak() {
        return Err(ProtoError::InvalidIdentity("weak public keys are forbidden".to_owned()));
    }
    Ok(verifying)
}

pub fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], ProtoError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| ProtoError::InvalidIdentity(format!("invalid padded base64: {error}")))?;
    decoded.try_into().map_err(|value: Vec<u8>| {
        ProtoError::InvalidIdentity(format!("expected {N} decoded bytes, got {}", value.len()))
    })
}
