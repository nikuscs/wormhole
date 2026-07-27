use http::{HeaderName, Version};

use super::{
    connection_tokens, hostname_from_authority, is_forwarding_header, is_hop_header, version_string,
};

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
fn http_versions_have_stable_wire_names() {
    assert_eq!(version_string(Version::HTTP_11), "HTTP/1.1");
    assert_eq!(version_string(Version::HTTP_2), "HTTP/2");
}
