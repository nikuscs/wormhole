use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{ClientHandshake, HandshakeStep, KeyDecision, ServerHandshake};
use crate::{
    ProtoError,
    frames::{ControlFrame, DenyReason, Limits, PROTO_VERSION},
    keys::Identity,
};

fn limits() -> Limits {
    Limits { max_binds: 4, max_streams: 32 }
}

fn take_reply(step: HandshakeStep) -> ControlFrame {
    match step {
        HandshakeStep::Reply(reply)
        | HandshakeStep::Done { reply: Some(reply), .. }
        | HandshakeStep::Failed { reply: Some(reply), .. } => reply,
        other => panic!("expected handshake reply, got {other:?}"),
    }
}

#[test]
fn client_and_server_complete_happy_path() {
    let identity = Identity::generate();
    let public_key = identity.public_base64();
    let mut client = ClientHandshake::new(identity, "relay.example.com", "test-client");
    let mut server = ServerHandshake::new(
        "relay.example.com",
        limits(),
        Some("welcome".to_owned()),
        move |presented| {
            if presented == public_key { KeyDecision::Authorized } else { KeyDecision::Unknown }
        },
    );

    let challenge = take_reply(server.step(&client.hello()).expect("hello must succeed"));
    let auth = take_reply(client.step(&challenge).expect("challenge must succeed"));
    let server_done = server.step(&auth).expect("auth must succeed");
    let welcome_frame = take_reply(server_done.clone());
    let client_done = client.step(&welcome_frame).expect("welcome must succeed");

    let HandshakeStep::Done { welcome: server_welcome, .. } = server_done else {
        panic!("server must complete");
    };
    let HandshakeStep::Done { welcome: client_welcome, reply: None } = client_done else {
        panic!("client must complete");
    };
    assert_eq!(client_welcome, server_welcome);
    assert_eq!(client_welcome.motd.as_deref(), Some("welcome"));
}

#[test]
fn unknown_key_is_denied() {
    let mut client =
        ClientHandshake::new(Identity::generate(), "relay.example.com", "unauthorized-client");
    let mut server =
        ServerHandshake::new("relay.example.com", limits(), None, |_| KeyDecision::Unknown);

    let step = server.step(&client.hello()).expect("denial is a valid handshake step");
    let denied = take_reply(step.clone());

    assert!(matches!(step, HandshakeStep::Failed { reason: DenyReason::UnknownKey, .. }));
    assert!(matches!(
        client.step(&denied).expect("client must accept denial"),
        HandshakeStep::Failed { reason: DenyReason::UnknownKey, reply: None }
    ));
}

#[test]
fn auth_before_hello_is_a_protocol_error() {
    let mut server =
        ServerHandshake::new("relay.example.com", limits(), None, |_| KeyDecision::Authorized);
    let auth = ControlFrame::Auth { signature: "invalid".to_owned() };

    let error = server.step(&auth).expect_err("out-of-order auth must fail");

    assert!(matches!(error, ProtoError::Protocol(_)));
}

#[test]
fn version_mismatch_carries_expected_version() {
    let mut server =
        ServerHandshake::new("relay.example.com", limits(), None, |_| KeyDecision::Authorized);
    let hello = ControlFrame::Hello {
        proto: PROTO_VERSION + 1,
        client: "future-client".to_owned(),
        pubkey: Identity::generate().public_base64(),
    };

    let step = server.step(&hello).expect("version denial is a valid handshake step");
    let reply = take_reply(step.clone());

    assert!(matches!(
        step,
        HandshakeStep::Failed {
            reason: DenyReason::VersionMismatch { expected: PROTO_VERSION },
            ..
        }
    ));
    assert!(matches!(
        reply,
        ControlFrame::Denied { reason: DenyReason::VersionMismatch { expected: PROTO_VERSION } }
    ));
}

#[test]
fn mismatched_server_name_aborts_without_signature() {
    let mut client = ClientHandshake::new(Identity::generate(), "relay.example.com", "test-client");
    let challenge = ControlFrame::Challenge {
        nonce: STANDARD.encode([9_u8; 32]),
        server: "attacker.example.com".to_owned(),
    };

    let error = client.step(&challenge).expect_err("mismatched relay must fail");

    assert!(matches!(error, ProtoError::ServerNameMismatch { .. }));
    assert!(matches!(client.step(&challenge), Err(ProtoError::Protocol(_))));
}

#[test]
fn bad_signature_is_denied() {
    let identity = Identity::generate();
    let public_key = identity.public_base64();
    let client = ClientHandshake::new(identity, "relay.example.com", "test-client");
    let mut server = ServerHandshake::new("relay.example.com", limits(), None, move |presented| {
        if presented == public_key { KeyDecision::Authorized } else { KeyDecision::Unknown }
    });
    let _challenge = server.step(&client.hello()).expect("hello must succeed");
    let bad_auth = ControlFrame::Auth { signature: STANDARD.encode([0_u8; 64]) };

    let step = server.step(&bad_auth).expect("signature denial is a valid handshake step");

    assert!(matches!(step, HandshakeStep::Failed { reason: DenyReason::BadSignature, .. }));
}
