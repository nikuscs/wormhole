use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{ClientHandshake, HandshakeStep, KeyDecision, ServerHandshake};
use crate::{
    ProtoError,
    frames::{BindSpec, ControlFrame, DenyReason, EventKind, Limits, PROTO_VERSION, Persistence},
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
fn every_control_frame_has_a_stable_protocol_name() {
    let id = uuid::Uuid::nil();
    let limits = limits();
    let frames = vec![
        ControlFrame::Hello { proto: 2, client: String::new(), pubkey: String::new() },
        ControlFrame::Welcome { session: id, limits, motd: None },
        ControlFrame::Denied { reason: DenyReason::UnknownKey },
        ControlFrame::Bind {
            request: id,
            spec: BindSpec::Tcp { remote_port: None, persist: Persistence::Temporary },
            reservation: None,
        },
        ControlFrame::Unbind { bind: id, forget: false },
        ControlFrame::Unbound { bind: id },
        ControlFrame::ForgetReservation { reservation: id },
        ControlFrame::ForgotReservation { reservation: id },
        ControlFrame::BindReady { bind: id },
        ControlFrame::Bound {
            request: id,
            bind: id,
            urls: Vec::new(),
            persist: Persistence::Temporary,
            reservation: None,
            pending_buffered: 0,
            failed_buffered: 0,
        },
        ControlFrame::BindError { request: id, reason: String::new() },
        ControlFrame::BindActive { bind: id },
        ControlFrame::BufferedStatus { bind: id, pending: 0, failed: 0 },
        ControlFrame::Event { kind: EventKind::Info, msg: String::new() },
        ControlFrame::AckBuffered { bind: id, seq: 0 },
        ControlFrame::NackBuffered { bind: id, seq: 0, reason: String::new() },
        ControlFrame::Pong { seq: 0 },
    ];
    for frame in frames {
        assert!(!super::frame_name(&frame).is_empty());
    }
}

#[test]
fn client_and_server_complete_happy_path() {
    let identity = Identity::generate();
    let public_key = identity.public_base64();
    let mut client = ClientHandshake::new(&identity, "relay.example.com", "test-client");
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
fn malformed_challenge_nonce_fails_client_permanently() {
    let identity = Identity::generate();
    let mut client = ClientHandshake::new(&identity, "relay.example.com", "test-client");
    let error = client
        .step(&ControlFrame::Challenge {
            nonce: "not-base64".to_owned(),
            server: "relay.example.com".to_owned(),
        })
        .expect_err("invalid nonce");
    assert!(matches!(error, ProtoError::Protocol(_)));
    assert!(client.step(&ControlFrame::Ping { seq: 1 }).is_err());
}

#[test]
fn revoked_and_limited_keys_receive_specific_denials() {
    let identity = Identity::generate();
    for (decision, expected) in
        [(KeyDecision::Revoked, DenyReason::KeyRevoked), (KeyDecision::Limit, DenyReason::Limit)]
    {
        let client = ClientHandshake::new(&identity, "relay.example.com", "test-client");
        let mut server =
            ServerHandshake::new("relay.example.com", limits(), None, move |_| decision);
        let step = server.step(&client.hello()).expect("denial");
        assert!(matches!(step, HandshakeStep::Failed { reason, .. } if reason == expected));
    }
}

#[test]
fn unknown_key_is_denied() {
    let identity = Identity::generate();
    let mut client = ClientHandshake::new(&identity, "relay.example.com", "unauthorized-client");
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
    let identity = Identity::generate();
    let mut client = ClientHandshake::new(&identity, "relay.example.com", "test-client");
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
    let client = ClientHandshake::new(&identity, "relay.example.com", "test-client");
    let mut server = ServerHandshake::new("relay.example.com", limits(), None, move |presented| {
        if presented == public_key { KeyDecision::Authorized } else { KeyDecision::Unknown }
    });
    let _challenge = server.step(&client.hello()).expect("hello must succeed");
    let bad_auth = ControlFrame::Auth { signature: STANDARD.encode([0_u8; 64]) };

    let step = server.step(&bad_auth).expect("signature denial is a valid handshake step");

    assert!(matches!(step, HandshakeStep::Failed { reason: DenyReason::BadSignature, .. }));
}
