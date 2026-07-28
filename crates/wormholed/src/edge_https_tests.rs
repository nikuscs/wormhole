use http::{HeaderName, Request, Version};

use super::{
    connection_tokens, hostname_from_authority, is_forwarding_header, is_hop_header,
    valid_websocket_request, version_string,
};
use crate::edge_types::forwarded_node;

#[test]
fn authority_strips_public_port() {
    assert_eq!(hostname_from_authority("demo.tun.example.com:8443"), Some("demo.tun.example.com"));
    assert_eq!(hostname_from_authority(""), None);
}

#[test]
fn edge_removes_hop_and_untrusted_forwarding_headers() {
    assert!(is_hop_header(&HeaderName::from_static("connection")));
    assert!(is_hop_header(&HeaderName::from_static("transfer-encoding")));
    assert!(is_forwarding_header(&HeaderName::from_static("forwarded")));
    assert!(!is_hop_header(&HeaderName::from_static("content-type")));
    assert_eq!(
        connection_tokens(["keep-alive, X-Private"].into_iter()),
        ["keep-alive", "x-private"]
    );
}

#[test]
fn forwarded_nodes_quote_bracketed_ipv6() {
    assert_eq!(forwarded_node("192.0.2.1".parse().expect("IPv4")), "192.0.2.1");
    assert_eq!(forwarded_node("2001:db8::1".parse().expect("IPv6")), "\"[2001:db8::1]\"");
}

#[test]
fn websocket_upgrade_rejects_wrong_origin_and_non_apex_host() {
    assert!(valid_websocket_request(&websocket_request("wormhole.test", None), "wormhole.test"));
    assert!(valid_websocket_request(
        &websocket_request("wormhole.test", Some("https://wormhole.test")),
        "wormhole.test"
    ));
    assert!(!valid_websocket_request(
        &websocket_request("wormhole.test", Some("https://attacker.test")),
        "wormhole.test"
    ));
    assert!(!valid_websocket_request(
        &websocket_request("demo.wormhole.test", None),
        "wormhole.test"
    ));
}

fn websocket_request(host: &str, origin: Option<&str>) -> Request<()> {
    let mut request = Request::builder()
        .method("GET")
        .uri("/_wormhole/ws")
        .header("host", host)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.body(()).expect("request")
}

#[test]
fn http_versions_have_stable_wire_names() {
    assert_eq!(version_string(Version::HTTP_11), "HTTP/1.1");
    assert_eq!(version_string(Version::HTTP_2), "HTTP/2");
}
