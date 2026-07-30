use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use super::{IfaceResolver, InterfaceInfo};

fn fake_interfaces() -> Vec<InterfaceInfo> {
    vec![
        InterfaceInfo {
            name: "en0".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))],
            is_default: true,
        },
        InterfaceInfo {
            name: "utun3".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(100, 100, 20, 4))],
            is_default: false,
        },
        InterfaceInfo {
            name: "docker0".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1))],
            is_default: false,
        },
    ]
}

#[test]
fn fake_interfaces_produce_builtin_and_named_aliases() {
    let resolver = IfaceResolver::with_source(BTreeMap::new(), Arc::new(fake_interfaces));
    let aliases = resolver.discover();
    let find = |name: &str| aliases.iter().find(|alias| alias.alias == name).map(|alias| alias.ip);

    assert_eq!(find("localhost"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(find("lan"), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
    assert_eq!(find("tailscale"), Some(IpAddr::V4(Ipv4Addr::new(100, 100, 20, 4))));
    assert_eq!(find("docker"), Some(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1))));
    assert_eq!(find("en0"), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
}

#[test]
fn resolver_always_resolves_localhost_and_user_literals() {
    let mut aliases = BTreeMap::new();
    aliases.insert("db-box".to_owned(), "192.168.1.40".to_owned());
    let resolver = IfaceResolver::new(aliases);

    assert_eq!(resolver.resolve("localhost").expect("localhost"), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        resolver.resolve("db-box").expect("user alias"),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))
    );
}
