use super::{DirectRoute, direct_route, valid_hostname};

#[test]
fn health_and_apex_misses_bypass_the_durable_object() {
    assert_eq!(
        direct_route("relay.example.com", "relay.example.com", "/health", true),
        DirectRoute::Health
    );
    assert_eq!(
        direct_route("relay.example.com", "relay.example.com", "/health", false),
        DirectRoute::NotFound
    );
    assert_eq!(
        direct_route("relay.example.com", "relay.example.com", "/missing", true),
        DirectRoute::NotFound
    );
}

#[test]
fn control_and_public_hosts_reach_the_durable_object() {
    assert!(valid_hostname("relay.example.com", "relay.example.com", "example.com"));
    assert!(valid_hostname("app.example.com", "relay.example.com", "example.com"));
    assert!(!valid_hostname("example.com", "relay.example.com", "example.com"));
    assert!(!valid_hostname("app.other.com", "relay.example.com", "example.com"));
    assert_eq!(
        direct_route("relay.example.com", "relay.example.com", "/_wormhole/ws", true),
        DirectRoute::DurableObject
    );
    assert_eq!(
        direct_route("relay.example.com", "relay.example.com", "/_wormhole/admin/invites", true,),
        DirectRoute::DurableObject
    );
    assert_eq!(
        direct_route("app.example.com", "relay.example.com", "/health", true),
        DirectRoute::DurableObject
    );
}
