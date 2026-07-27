//! Edge authentication using live credentials or persisted verification material.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::{Request, body::Incoming};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::registry::BindHandle;

static BASIC_AUTH_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);

pub async fn authorized(request: &Request<Incoming>, handle: &BindHandle) -> bool {
    let Some(value) = request.headers().get(http::header::AUTHORIZATION) else {
        return handle.auth.is_none() && handle.auth_verifier().is_none();
    };
    let provided = value.as_bytes();
    if let Some(auth) = &handle.auth {
        let basic = auth.basic.as_ref().is_some_and(|credential| {
            let expected = format!("Basic {}", STANDARD.encode(credential));
            constant_time_eq(provided, expected.as_bytes())
        });
        let bearer = auth.bearer.as_ref().is_some_and(|secret| {
            let expected = format!("Bearer {secret}");
            constant_time_eq(provided, expected.as_bytes())
        });
        return basic || bearer;
    }
    let Some(verifier) = handle.auth_verifier() else {
        return true;
    };
    if let Some(secret_hash) = verifier.bearer_sha256
        && let Some(secret) = provided.strip_prefix(b"Bearer ")
    {
        let candidate = STANDARD.encode(Sha256::digest(secret));
        if constant_time_eq(candidate.as_bytes(), secret_hash.as_bytes()) {
            return true;
        }
    }
    let Some(stored) = verifier.basic_argon2 else {
        return false;
    };
    let Some(encoded) = provided.strip_prefix(b"Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(permit) = BASIC_AUTH_SLOTS.try_acquire() else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_basic(&stored, &decoded)
    })
    .await
    .unwrap_or(false)
}

fn verify_basic(stored: &str, provided: &[u8]) -> bool {
    let Some((stored_user, hash)) = stored.split_once(':') else {
        return false;
    };
    let Ok(provided) = std::str::from_utf8(provided) else {
        return false;
    };
    let Some((provided_user, password)) = provided.split_once(':') else {
        return false;
    };
    let user_matches = constant_time_eq(stored_user.as_bytes(), provided_user.as_bytes());
    let password_matches = PasswordHash::new(hash)
        .is_ok_and(|hash| Argon2::default().verify_password(password.as_bytes(), &hash).is_ok());
    user_matches && password_matches
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).into()
}

#[cfg(test)]
#[path = "edge_auth_tests.rs"]
mod tests;
