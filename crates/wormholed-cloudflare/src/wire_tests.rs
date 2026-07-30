use uuid::Uuid;
use wormhole_proto::{
    frames::{ControlFrame, Persistence},
    mux::WsMessage,
};

use super::{
    CONTROL_DATA, control_frame, is_forwarding_header, response_allows_body,
    should_forward_request_header, take_control_frames,
};

#[test]
fn control_frames_match_existing_websocket_fallback_framing() {
    let frame = ControlFrame::Unbind { bind: Uuid::from_u128(7), forget: true };
    let websocket = control_frame(&frame).expect("encode");
    let message = WsMessage::decode(&websocket).expect("mux envelope");
    assert_eq!(message.channel, 0);
    assert_eq!(message.payload[0], CONTROL_DATA);
    let mut bytes = message.payload[1..].to_vec();
    assert_eq!(take_control_frames(&mut bytes).expect("control frame"), [frame]);
    assert!(bytes.is_empty());
}

#[test]
fn response_body_matrix_matches_fetch_semantics() {
    assert!(response_allows_body("GET", 200));
    assert!(response_allows_body("POST", 206));
    assert!(!response_allows_body("HEAD", 200));
    for status in [101, 204, 205, 304] {
        assert!(!response_allows_body("GET", status));
    }
}

#[test]
fn websocket_request_preserves_upgrade_without_negotiating_extensions() {
    assert!(should_forward_request_header("connection", true));
    assert!(should_forward_request_header("upgrade", true));
    assert!(should_forward_request_header("sec-websocket-key", true));
    assert!(!should_forward_request_header("sec-websocket-extensions", true));
    assert!(!should_forward_request_header("connection", false));
}

#[test]
fn trusted_forwarding_headers_include_the_public_host() {
    for name in ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"] {
        assert!(is_forwarding_header(name));
    }
    assert!(!is_forwarding_header("host"));
}

#[test]
fn persistent_bind_frame_round_trips_without_worker_specific_types() {
    let frame = ControlFrame::Bind {
        request: Uuid::from_u128(1),
        spec: wormhole_proto::frames::BindSpec::Http {
            host: Some("stable".to_owned()),
            auto_host: false,
            domain: Some("relay.example.com".to_owned()),
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
        },
        reservation: None,
    };
    let encoded = serde_json::to_vec(&frame).expect("serialize");
    assert_eq!(serde_json::from_slice::<ControlFrame>(&encoded).expect("deserialize"), frame);
}
