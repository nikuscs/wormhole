use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

use super::{verify_basic, verify_link_token};

#[test]
fn persisted_basic_verifier_accepts_only_original_credentials() {
    let salt = SaltString::encode_b64(&[7_u8; 16]).expect("salt");
    let hash = Argon2::default().hash_password(b"secret", &salt).expect("hash");
    let stored = format!("agent:{hash}");
    assert!(verify_basic(&stored, b"agent:secret"));
    assert!(!verify_basic(&stored, b"agent:wrong"));
    assert!(!verify_basic(&stored, b"other:secret"));
}

#[test]
fn signed_link_token_is_host_bound_and_expires() {
    let key = [9_u8; 32];
    let expiry = jiff::Timestamp::now().as_second() + 60;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
    mac.update(b"demo.example.com");
    mac.update(&expiry.to_be_bytes());
    let mut raw = expiry.to_be_bytes().to_vec();
    raw.extend_from_slice(&mac.finalize().into_bytes());
    let token = URL_SAFE_NO_PAD.encode(raw);
    assert_eq!(verify_link_token(&token, "demo.example.com", &key), Some(expiry));
    assert!(verify_link_token(&token, "other.example.com", &key).is_none());
}
