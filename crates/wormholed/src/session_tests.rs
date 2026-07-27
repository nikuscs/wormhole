use wormhole_proto::frames::EdgeAuth;

use super::build_auth_verifier;

#[test]
fn persisted_auth_contains_only_verification_material() {
    let verifier = build_auth_verifier(&EdgeAuth {
        basic: Some("agent:secret".to_owned()),
        bearer: Some("bearer-secret".to_owned()),
        link_key: Some("bGluay1rZXk=".to_owned()),
    })
    .expect("auth verifier must build");

    assert!(
        verifier.basic_argon2.as_deref().is_some_and(|value| {
            value.starts_with("agent:$argon2") && !value.contains("secret")
        })
    );
    assert_ne!(verifier.bearer_sha256.as_deref(), Some("bearer-secret"));
    assert_eq!(verifier.link_hmac_key.as_deref(), Some("bGluay1rZXk="));
}
