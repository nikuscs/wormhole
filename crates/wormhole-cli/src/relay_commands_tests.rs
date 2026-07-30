use super::{
    CloudflareDeployView, validate_domain, validate_domain_layout, validate_remote_name,
    validate_worker_name, worker_name,
};
use crate::output::HumanRender as _;

#[test]
fn deploy_identifiers_are_strict_and_deterministic() {
    assert_eq!(validate_domain("Relay.Example.com.").expect("domain"), "relay.example.com");
    assert!(validate_domain("localhost").is_err());
    assert!(validate_domain("*.example.com").is_err());
    assert!(validate_worker_name("wormhole-relay-a1b2c3d4").is_ok());
    assert!(validate_domain_layout("example.com", "relay.example.com").is_ok());
    assert!(validate_domain_layout("example.com", "example.com").is_err());
    assert!(validate_domain_layout("example.com", "relay.other.com").is_err());
    assert!(validate_worker_name("Invalid_Name").is_err());
    assert!(validate_remote_name("cloudflare_prod").is_ok());
    assert_eq!(worker_name("relay.example.com"), worker_name("relay.example.com"));
    assert_ne!(worker_name("relay.example.com"), worker_name("other.example.com"));
}

#[test]
fn deployment_output_never_contains_provider_credentials() {
    let view = CloudflareDeployView {
        status: "deployed",
        domain: "example.com".to_owned(),
        relay_domain: "relay.example.com".to_owned(),
        worker: "wormhole-example-a1b2c3d4".to_owned(),
        remote: Some("cloudflare".to_owned()),
        dns_records_created: vec!["relay.example.com".to_owned()],
        logs_enabled: false,
        waf_configured: false,
    };
    let rendered = view.render();
    assert!(rendered.contains("relay.example.com"));
    assert!(!rendered.to_ascii_lowercase().contains("token"));
    assert!(!rendered.to_ascii_lowercase().contains("secret"));
}
