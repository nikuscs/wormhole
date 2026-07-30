use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use super::{
    constant_time_eq, cookie_value, credential_digest, query_token, validate_link_key,
    verify_link_token_at, without_token,
};

#[test]
fn credential_digests_are_context_bound_and_deterministic() {
    let key = "0123456789abcdef0123456789abcdef";
    let basic = credential_digest(key, b"basic", "Basic dXNlcjpwYXNz");
    assert_eq!(basic, credential_digest(key, b"basic", "Basic dXNlcjpwYXNz"));
    assert_ne!(basic, credential_digest(key, b"bearer", "Basic dXNlcjpwYXNz"));
    assert!(!constant_time_eq(basic.as_bytes(), b"wrong"));
}

#[test]
fn share_tokens_validate_host_signature_and_expiry() {
    let key = [7_u8; 32];
    let expiry = 2_000_000_000_i64;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
    mac.update(b"demo.example.com");
    mac.update(&expiry.to_be_bytes());
    let mut token = expiry.to_be_bytes().to_vec();
    token.extend_from_slice(&mac.finalize().into_bytes());
    let token = URL_SAFE_NO_PAD.encode(token);

    assert_eq!(verify_link_token_at(&token, "demo.example.com", &key, expiry - 1), Some(expiry));
    assert_eq!(verify_link_token_at(&token, "other.example.com", &key, expiry - 1), None);
    assert_eq!(verify_link_token_at(&token, "demo.example.com", &key, expiry + 1), None);
}

#[test]
fn link_inputs_are_validated_and_removed_from_redirects() {
    assert!(validate_link_key(&STANDARD.encode([3_u8; 32])).is_ok());
    assert!(validate_link_key(&STANDARD.encode([3_u8; 8])).is_err());
    assert_eq!(query_token(Some("a=1&wh_token=secret&b=2")), Some("secret"));
    assert_eq!(without_token("/path", Some("a=1&wh_token=secret&b=2")), "/path?a=1&b=2");
    assert_eq!(cookie_value("a=1; wormhole_auth=secret; b=2", "wormhole_auth"), Some("secret"));
}
