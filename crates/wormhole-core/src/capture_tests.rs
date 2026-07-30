use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;
use wormhole_proto::frames::{HeaderField, HttpRequestHead, HttpResponseHead};

use super::CaptureContext;

fn head(uri: &str) -> HttpRequestHead {
    HttpRequestHead {
        method: "POST".to_owned(),
        uri: uri.to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField {
            name: "authorization".to_owned(),
            value_b64: STANDARD.encode("secret"),
        }],
    }
}

#[test]
fn capture_redacts_and_bounds_bodies() {
    let capture = CaptureContext::eligible(Uuid::now_v7(), &head("/hook"), false, 1024 * 1024)
        .expect("eligible");
    capture.request_bytes(&vec![1; 1024 * 1024 + 1]);
    capture.response_head(&HttpResponseHead {
        status: 200,
        version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
    });
    capture.response_bytes(&vec![2; 128 * 1024 + 1]);
    let captured = capture.finish_once("ok").expect("capture");
    assert!(captured.body_truncated);
    assert_eq!(captured.body.len(), 128 * 1024);
    assert!(captured.response_body_truncated);
    assert_ne!(captured.headers[0].value_b64, STANDARD.encode("secret"));
}

#[test]
fn oversized_body_keeps_128k_prefix_even_with_smaller_complete_limit() {
    let capture =
        CaptureContext::eligible(Uuid::now_v7(), &head("/hook"), false, 1024).expect("eligible");
    capture.request_bytes(&vec![1; 64 * 1024]);
    capture.request_bytes(&vec![2; 64 * 1024]);
    capture.request_bytes(&vec![3; 64 * 1024]);
    let captured = capture.finish_once("ok").expect("capture");
    assert!(captured.body_truncated);
    assert_eq!(captured.body.len(), 128 * 1024);
}

#[test]
fn complete_body_below_configured_limit_remains_replayable() {
    let capture = CaptureContext::eligible(Uuid::now_v7(), &head("/hook"), false, 1024 * 1024)
        .expect("eligible");
    capture.request_bytes(&vec![1; 256 * 1024]);
    capture.complete_request();
    let captured = capture.finish_once("ok").expect("capture");
    assert!(!captured.body_truncated);
    assert_eq!(captured.body.len(), 256 * 1024);
}

#[test]
fn static_assets_are_ignored() {
    let mut request = head("/app.js");
    request.method = "GET".to_owned();
    assert!(CaptureContext::eligible(Uuid::now_v7(), &request, false, 1024 * 1024).is_none());
}
