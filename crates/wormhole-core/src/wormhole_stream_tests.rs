use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use wormhole_proto::frames::{HeaderField, HttpRequestHead};

use super::{BoxError, build_request};

fn body() -> super::ClientBody {
    Full::new(Bytes::new()).map_err(|never| -> BoxError { match never {} }).boxed_unsync()
}

#[test]
fn local_request_strips_connection_nominated_headers() {
    let head = HttpRequestHead {
        method: "GET".to_owned(),
        uri: "/path".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![
            field("host", "demo.example"),
            field("connection", "keep-alive, x-private"),
            field("x-private", "secret"),
            field("keep-alive", "timeout=5"),
        ],
    };

    let request = build_request(head, body(), false).expect("request");

    assert_eq!(request.uri(), "/path");
    assert_eq!(request.headers().get("host").expect("host"), "demo.example");
    assert!(!request.headers().contains_key("connection"));
    assert!(!request.headers().contains_key("x-private"));
}

#[test]
fn local_upgrade_request_preserves_required_upgrade_headers() {
    let head = HttpRequestHead {
        method: "GET".to_owned(),
        uri: "/socket".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![field("connection", "upgrade"), field("upgrade", "websocket")],
    };

    let request = build_request(head, body(), true).expect("upgrade request");

    assert_eq!(request.headers().get("connection").expect("connection"), "upgrade");
    assert_eq!(request.headers().get("upgrade").expect("upgrade"), "websocket");
}

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) }
}
