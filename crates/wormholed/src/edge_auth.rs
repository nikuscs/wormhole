//! Edge authentication using live credentials or persisted verification material.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use hyper::{Request, body::Incoming};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::registry::BindHandle;

pub enum LinkDecision {
    NotConfigured,
    Authorized,
    Redirect { location: String, cookie: String },
    Denied,
}

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
    let Ok(permit) = BASIC_AUTH_SLOTS.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_basic(&stored, &decoded)
    })
    .await
    .unwrap_or(false)
}

pub fn link_decision<B>(request: &Request<B>, handle: &BindHandle, host: &str) -> LinkDecision {
    let encoded_key = handle
        .auth
        .as_ref()
        .and_then(|auth| auth.link_key.clone())
        .or_else(|| handle.auth_verifier().and_then(|verifier| verifier.link_hmac_key));
    let Some(encoded_key) = encoded_key else {
        return LinkDecision::NotConfigured;
    };
    let Ok(key) = STANDARD.decode(&encoded_key) else {
        return LinkDecision::Denied;
    };
    if let Some(token) = query_token(request.uri().query()) {
        let Some(expiry) = verify_link_token(token, host, &key) else {
            return LinkDecision::Denied;
        };
        let location = without_token(request.uri());
        let cookie = format!(
            "wormhole_auth={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            expiry.saturating_sub(jiff::Timestamp::now().as_second()).max(0)
        );
        return LinkDecision::Redirect { location, cookie };
    }
    let cookie =
        request.headers().get(http::header::COOKIE).and_then(|value| value.to_str().ok()).and_then(
            |cookies| {
                cookies.split(';').find_map(|cookie| cookie.trim().strip_prefix("wormhole_auth="))
            },
        );
    if cookie.is_some_and(|token| verify_link_token(token, host, &key).is_some()) {
        LinkDecision::Authorized
    } else {
        LinkDecision::Denied
    }
}

fn query_token(query: Option<&str>) -> Option<&str> {
    query?.split('&').find_map(|part| part.strip_prefix("wh_token="))
}

fn without_token(uri: &http::Uri) -> String {
    let path = uri.path();
    let query = uri
        .query()
        .map(|query| {
            query
                .split('&')
                .filter(|part| !part.starts_with("wh_token="))
                .collect::<Vec<_>>()
                .join("&")
        })
        .filter(|query| !query.is_empty());
    query.map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"))
}

fn verify_link_token(token: &str, host: &str, key: &[u8]) -> Option<i64> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let expiry = i64::from_be_bytes(decoded.get(..8)?.try_into().ok()?);
    if expiry < jiff::Timestamp::now().as_second() {
        return None;
    }
    let supplied = decoded.get(8..)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(host.as_bytes());
    mac.update(&expiry.to_be_bytes());
    let expected = mac.finalize().into_bytes();
    constant_time_eq(supplied, &expected).then_some(expiry)
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
