use super::{allowed_host, redirect_location};

#[test]
fn redirect_includes_nonstandard_https_port_and_path() {
    assert_eq!(
        redirect_location("demo.tun.example.com", "/hooks?event=push", 8443),
        "https://demo.tun.example.com:8443/hooks?event=push"
    );
    assert_eq!(
        redirect_location("demo.tun.example.com", "/", 443),
        "https://demo.tun.example.com/"
    );
    let domains = ["tun.example.com".to_owned()];
    assert!(allowed_host("DEMO.tun.example.com", &domains));
    assert!(allowed_host("tun.example.com", &domains));
    assert!(!allowed_host("evil.example", &domains));
    assert!(!allowed_host("a.b.tun.example.com", &domains));
}
