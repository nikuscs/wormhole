use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use worker::{Env, Headers, Request, Response, Result};
use wormhole_proto::frames::EdgeAuth;

use crate::storage::BindRow;

type HmacSha256 = Hmac<Sha256>;
const COOKIE_NAME: &str = "wormhole_auth";
const MIN_EDGE_AUTH_KEY_BYTES: usize = 32;
const MIN_LINK_KEY_BYTES: usize = 32;

#[derive(Default)]
pub struct Verifier {
    pub basic_hmac: Option<String>,
    pub bearer_hmac: Option<String>,
    pub link_hmac_key: Option<String>,
}

pub fn build(env: &Env, auth: Option<&EdgeAuth>) -> std::result::Result<Verifier, String> {
    let Some(auth) = auth else { return Ok(Verifier::default()) };
    if auth.basic.as_deref().is_some_and(|value| !value.contains(':')) {
        return Err("basic auth must be user:password".to_owned());
    }
    if auth.bearer.as_deref().is_some_and(str::is_empty) {
        return Err("bearer token must not be empty".to_owned());
    }
    let link_hmac_key =
        auth.link_key.as_deref().map(validate_link_key).transpose()?.map(str::to_owned);
    let needs_key = auth.basic.is_some() || auth.bearer.is_some();
    let key = needs_key.then(|| edge_auth_key(env)).transpose()?;
    Ok(Verifier {
        basic_hmac: auth.basic.as_deref().map(|credential| {
            credential_digest(
                key.as_deref().expect("edge auth key loaded"),
                b"basic",
                &format!("Basic {}", STANDARD.encode(credential)),
            )
        }),
        bearer_hmac: auth.bearer.as_deref().map(|token| {
            credential_digest(
                key.as_deref().expect("edge auth key loaded"),
                b"bearer",
                &format!("Bearer {token}"),
            )
        }),
        link_hmac_key,
    })
}

pub fn authorize(
    request: &Request,
    env: &Env,
    bind: &BindRow,
    hostname: &str,
) -> Result<Option<Response>> {
    if !bind.has_auth() {
        return Ok(None);
    }
    if let Some(value) = request.headers().get("authorization")?
        && credential_authorized(env, bind, &value)
    {
        return Ok(None);
    }
    if let Some(encoded_key) = bind.link_hmac_key.as_deref() {
        return link_response(request, hostname, encoded_key);
    }
    unauthorized(bind.basic_hmac.is_some()).map(Some)
}

fn credential_authorized(env: &Env, bind: &BindRow, provided: &str) -> bool {
    let Ok(key) = edge_auth_key(env) else { return false };
    let candidate = if provided.starts_with("Basic ") {
        bind.basic_hmac.as_deref().map(|expected| (b"basic".as_slice(), expected))
    } else if provided.starts_with("Bearer ") {
        bind.bearer_hmac.as_deref().map(|expected| (b"bearer".as_slice(), expected))
    } else {
        None
    };
    candidate.is_some_and(|(context, expected)| {
        constant_time_eq(credential_digest(&key, context, provided).as_bytes(), expected.as_bytes())
    })
}

fn link_response(request: &Request, hostname: &str, encoded_key: &str) -> Result<Option<Response>> {
    let key = match STANDARD.decode(encoded_key) {
        Ok(key) if key.len() >= MIN_LINK_KEY_BYTES => key,
        _ => return forbidden().map(Some),
    };
    let url = request.url()?;
    if let Some(token) = query_token(url.query()) {
        let Some(expiry) = verify_link_token_at(token, hostname, &key, now_seconds()) else {
            return forbidden().map(Some);
        };
        return redirect(&without_token(url.path(), url.query()), token, expiry).map(Some);
    }
    let cookie_authorized = request.headers().get("cookie")?.is_some_and(|cookies| {
        cookie_value(&cookies, COOKIE_NAME).is_some_and(|token| {
            verify_link_token_at(token, hostname, &key, now_seconds()).is_some()
        })
    });
    if cookie_authorized { Ok(None) } else { forbidden().map(Some) }
}

fn redirect(location: &str, token: &str, expiry: i64) -> Result<Response> {
    let max_age = expiry.saturating_sub(now_seconds()).max(0);
    let headers = Headers::new();
    headers.set("location", location)?;
    headers.set(
        "set-cookie",
        &format!(
            "{COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"
        ),
    )?;
    headers.set("cache-control", "no-store")?;
    headers.set("referrer-policy", "no-referrer")?;
    Ok(Response::empty()?.with_status(302).with_headers(headers))
}

fn unauthorized(basic: bool) -> Result<Response> {
    let headers = Headers::new();
    headers.set("cache-control", "no-store")?;
    if basic {
        headers.set("www-authenticate", "Basic realm=\"wormhole\"")?;
    }
    Ok(Response::ok("Unauthorized")?.with_status(401).with_headers(headers))
}

fn forbidden() -> Result<Response> {
    let headers = Headers::new();
    headers.set("cache-control", "no-store")?;
    Ok(Response::ok("Forbidden")?.with_status(403).with_headers(headers))
}

fn edge_auth_key(env: &Env) -> std::result::Result<String, String> {
    let key = env
        .secret("EDGE_AUTH_KEY")
        .map_err(|_| "EDGE_AUTH_KEY secret is required for Basic/Bearer edge auth".to_owned())?
        .to_string();
    if key.len() < MIN_EDGE_AUTH_KEY_BYTES {
        return Err("EDGE_AUTH_KEY must contain at least 32 bytes".to_owned());
    }
    Ok(key)
}

fn validate_link_key(encoded: &str) -> std::result::Result<&str, String> {
    match STANDARD.decode(encoded) {
        Ok(key) if key.len() >= MIN_LINK_KEY_BYTES => Ok(encoded),
        _ => Err("share-link key must be padded base64 containing at least 32 bytes".to_owned()),
    }
}

fn credential_digest(key: &str, context: &[u8], provided: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"wormhole-edge-auth-v1\0");
    mac.update(context);
    mac.update(b"\0");
    mac.update(provided.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn verify_link_token_at(token: &str, host: &str, key: &[u8], now: i64) -> Option<i64> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let expiry = i64::from_be_bytes(decoded.get(..8)?.try_into().ok()?);
    if expiry < now {
        return None;
    }
    let supplied = decoded.get(8..)?;
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(host.as_bytes());
    mac.update(&expiry.to_be_bytes());
    let expected = mac.finalize().into_bytes();
    constant_time_eq(supplied, &expected).then_some(expiry)
}

fn query_token(query: Option<&str>) -> Option<&str> {
    query?.split('&').find_map(|part| part.strip_prefix("wh_token="))
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|cookie| cookie.trim().strip_prefix(&format!("{name}=")))
}

fn without_token(path: &str, query: Option<&str>) -> String {
    let query = query
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn now_seconds() -> i64 {
    i64::try_from(worker::Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

#[cfg(test)]
#[path = "edge_auth_tests.rs"]
mod tests;
