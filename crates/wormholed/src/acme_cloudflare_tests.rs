use super::zone_candidates;

#[test]
fn parent_zones_are_discovered_from_most_to_least_specific() {
    assert_eq!(
        zone_candidates("tun.eu.example.com"),
        ["tun.eu.example.com", "eu.example.com", "example.com"]
    );
}
