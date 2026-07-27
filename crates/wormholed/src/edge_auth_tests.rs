use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use super::verify_basic;

#[test]
fn persisted_basic_verifier_accepts_only_original_credentials() {
    let salt = SaltString::encode_b64(&[7_u8; 16]).expect("salt");
    let hash = Argon2::default().hash_password(b"secret", &salt).expect("hash");
    let stored = format!("agent:{hash}");
    assert!(verify_basic(&stored, b"agent:secret"));
    assert!(!verify_basic(&stored, b"agent:wrong"));
    assert!(!verify_basic(&stored, b"other:secret"));
}
