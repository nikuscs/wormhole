use std::sync::Arc;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use http::Request;
use parking_lot::RwLock;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use wormhole_proto::frames::{EdgeAuth, Persistence};

use super::{LinkDecision, authorized, link_decision, verify_basic, verify_link_token};
use crate::{
    db::{AuthVerifier, PersistedBindSpec, PersistedEndpoint},
    registry::{BindHandle, BindState},
};

#[test]
fn persisted_basic_verifier_accepts_only_original_credentials() {
    let stored = basic_verifier();
    assert!(verify_basic(&stored, b"agent:secret"));
    assert!(!verify_basic(&stored, b"agent:wrong"));
    assert!(!verify_basic(&stored, b"other:secret"));
    assert!(!verify_basic("malformed", b"agent:secret"));
    assert!(!verify_basic(&stored, b"malformed"));
    assert!(!verify_basic(&stored, &[0xff]));
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

#[tokio::test]
async fn live_auth_accepts_basic_bearer_and_public_requests() {
    let public = handle(None, None);
    assert!(authorized(&request(None), &public).await);
    assert!(authorized(&request(Some("anything")), &public).await);

    let live = handle(
        Some(EdgeAuth {
            basic: Some("agent:secret".to_owned()),
            bearer: Some("token".to_owned()),
            link_key: None,
        }),
        None,
    );
    assert!(!authorized(&request(None), &live).await);
    assert!(
        authorized(&request(Some(&format!("Basic {}", STANDARD.encode("agent:secret")))), &live)
            .await
    );
    assert!(authorized(&request(Some("Bearer token")), &live).await);
    assert!(!authorized(&request(Some("Bearer wrong")), &live).await);
}

#[tokio::test]
async fn persisted_auth_checks_bearer_digest_and_argon2_material() {
    let verifier = AuthVerifier {
        basic_argon2: Some(basic_verifier()),
        bearer_sha256: Some(STANDARD.encode(Sha256::digest(b"token"))),
        link_hmac_key: None,
    };
    let persisted = handle(None, Some(verifier));
    assert!(authorized(&request(Some("Bearer token")), &persisted).await);
    assert!(!authorized(&request(Some("Bearer wrong")), &persisted).await);
    assert!(
        authorized(
            &request(Some(&format!("Basic {}", STANDARD.encode("agent:secret")))),
            &persisted
        )
        .await
    );
    assert!(!authorized(&request(Some("Basic !!!")), &persisted).await);
    assert!(!authorized(&request(Some("Digest token")), &persisted).await);

    let bearer_only = handle(
        None,
        Some(AuthVerifier {
            basic_argon2: None,
            bearer_sha256: Some(STANDARD.encode(Sha256::digest(b"token"))),
            link_hmac_key: None,
        }),
    );
    assert!(!authorized(&request(Some("Basic YQ==")), &bearer_only).await);
}

#[test]
fn signed_link_query_redirects_then_cookie_authorizes() {
    let key = [9_u8; 32];
    let expiry = jiff::Timestamp::now().as_second() + 60;
    let token = link_token("demo.example.com", expiry, &key);
    let handle = handle(
        Some(EdgeAuth { basic: None, bearer: None, link_key: Some(STANDARD.encode(key)) }),
        None,
    );
    let query = Request::builder()
        .uri(format!("/path?a=1&wh_token={token}&b=2"))
        .body(())
        .expect("request");
    match link_decision(&query, &handle, "demo.example.com") {
        LinkDecision::Redirect { location, cookie } => {
            assert_eq!(location, "/path?a=1&b=2");
            assert!(cookie.contains(&format!("wormhole_auth={token}")));
            assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
        }
        _ => panic!("expected redirect"),
    }
    let cookie = Request::builder()
        .uri("/path")
        .header("cookie", format!("other=x; wormhole_auth={token}"))
        .body(())
        .expect("request");
    assert!(matches!(
        link_decision(&cookie, &handle, "demo.example.com"),
        LinkDecision::Authorized
    ));
    assert!(matches!(link_decision(&cookie, &handle, "other.example.com"), LinkDecision::Denied));
}

#[test]
fn link_policy_handles_absence_invalid_keys_and_invalid_tokens() {
    let none = handle(None, None);
    assert!(matches!(link_decision(&request(None), &none, "host"), LinkDecision::NotConfigured));
    let invalid =
        handle(Some(EdgeAuth { basic: None, bearer: None, link_key: Some("!".to_owned()) }), None);
    assert!(matches!(link_decision(&request(None), &invalid, "host"), LinkDecision::Denied));

    let key = [4_u8; 32];
    let persisted = handle(
        None,
        Some(AuthVerifier {
            basic_argon2: None,
            bearer_sha256: None,
            link_hmac_key: Some(STANDARD.encode(key)),
        }),
    );
    let invalid_token = Request::builder().uri("/?wh_token=bad").body(()).expect("request");
    assert!(matches!(link_decision(&invalid_token, &persisted, "host"), LinkDecision::Denied));
    assert!(verify_link_token("bad", "host", &key).is_none());
    let expired = link_token("host", jiff::Timestamp::now().as_second() - 1, &key);
    assert!(verify_link_token(&expired, "host", &key).is_none());
}

fn basic_verifier() -> String {
    let salt = SaltString::encode_b64(&[7_u8; 16]).expect("salt");
    let hash = Argon2::default().hash_password(b"secret", &salt).expect("hash");
    format!("agent:{hash}")
}

fn request(authorization: Option<&str>) -> Request<()> {
    let mut builder = Request::builder().uri("/");
    if let Some(value) = authorization {
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    builder.body(()).expect("request")
}

fn handle(auth: Option<EdgeAuth>, verifier: Option<AuthVerifier>) -> Arc<BindHandle> {
    Arc::new(BindHandle {
        bind_id: Uuid::now_v7(),
        key_fpr: "owner".to_owned(),
        persist: Persistence::Persistent,
        buffer_policy: None,
        auth,
        auth_verifier: RwLock::new(verifier),
        spec: PersistedBindSpec::Http {
            host: Some("demo".to_owned()),
            domain: Some("example.com".to_owned()),
            persist: Persistence::Persistent,
            buffer: None,
        },
        endpoint: PersistedEndpoint::Hostname("demo.example.com".to_owned()),
        state: RwLock::new(BindState::Offline),
        session_tx: RwLock::new(None),
        reservation: Some(Uuid::now_v7()),
    })
}

fn link_token(host: &str, expiry: i64, key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(host.as_bytes());
    mac.update(&expiry.to_be_bytes());
    let mut raw = expiry.to_be_bytes().to_vec();
    raw.extend_from_slice(&mac.finalize().into_bytes());
    URL_SAFE_NO_PAD.encode(raw)
}
