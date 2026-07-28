//! Offline signed share-link minting.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::DriverError;

pub fn generate_link_key() -> String {
    STANDARD.encode(rand::random::<[u8; 32]>())
}

pub fn mint_share_url(
    public_url: &str,
    path: &str,
    encoded_key: &str,
    expiry_unix: i64,
) -> Result<String, DriverError> {
    let uri = public_url
        .parse::<http::Uri>()
        .map_err(|error| DriverError::Capability(format!("invalid endpoint URL: {error}")))?;
    let host =
        uri.host().ok_or_else(|| DriverError::Capability("endpoint URL has no host".to_owned()))?;
    let key = STANDARD
        .decode(encoded_key)
        .map_err(|error| DriverError::Capability(format!("invalid link key: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|error| DriverError::Capability(error.to_string()))?;
    mac.update(host.as_bytes());
    mac.update(&expiry_unix.to_be_bytes());
    let mut token = expiry_unix.to_be_bytes().to_vec();
    token.extend_from_slice(&mac.finalize().into_bytes());
    let separator = if path.contains('?') { '&' } else { '?' };
    let authority = uri.authority().map_or(host, http::uri::Authority::as_str);
    Ok(format!(
        "{}://{authority}{path}{separator}wh_token={}",
        uri.scheme_str().unwrap_or("https"),
        URL_SAFE_NO_PAD.encode(token)
    ))
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod tests;
