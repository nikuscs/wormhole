//! On-demand network-interface alias discovery and resolution.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::Arc,
};

use crate::error::IfaceError;

/// One discovered alias mapping.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct IfaceAlias {
    /// Stable alias used in configuration.
    pub alias: String,
    /// Operating-system interface name.
    pub iface: String,
    /// Selected interface address.
    #[schema(value_type = String)]
    pub ip: IpAddr,
}

#[derive(Debug, Clone)]
pub(crate) struct InterfaceInfo {
    name: String,
    ips: Vec<IpAddr>,
    is_default: bool,
}

/// Resolver with user aliases layered over refreshed system discovery.
#[derive(Clone)]
pub struct IfaceResolver {
    user_aliases: BTreeMap<String, String>,
    source: Arc<dyn Fn() -> Vec<InterfaceInfo> + Send + Sync>,
}

impl IfaceResolver {
    /// Creates an alias resolver.
    pub fn new(user_aliases: BTreeMap<String, String>) -> Self {
        Self { user_aliases, source: Arc::new(system_interfaces) }
    }

    #[cfg(test)]
    pub(crate) fn with_source(
        user_aliases: BTreeMap<String, String>,
        source: Arc<dyn Fn() -> Vec<InterfaceInfo> + Send + Sync>,
    ) -> Self {
        Self { user_aliases, source }
    }

    /// Discovers builtin aliases and every real interface by name.
    pub fn discover(&self) -> Vec<IfaceAlias> {
        discover_from((self.source)())
    }

    /// Resolves user alias, builtin alias, interface name, literal IP, then hostname.
    pub fn resolve(&self, alias_or_host: &str) -> Result<IpAddr, IfaceError> {
        let candidate = self.user_aliases.get(alias_or_host).map_or(alias_or_host, String::as_str);
        if let Some(alias) =
            discover_from((self.source)()).into_iter().find(|alias| alias.alias == candidate)
        {
            return Ok(alias.ip);
        }
        if let Ok(ip) = candidate.parse() {
            return Ok(ip);
        }
        (candidate, 0)
            .to_socket_addrs()?
            .next()
            .map(|address| address.ip())
            .ok_or_else(|| IfaceError::Unresolved(candidate.to_owned()))
    }
}

fn discover_from(interfaces: Vec<InterfaceInfo>) -> Vec<IfaceAlias> {
    let mut aliases = vec![IfaceAlias {
        alias: "localhost".to_owned(),
        iface: "lo".to_owned(),
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    }];
    if let Some((iface, ip)) = first_ipv4(interfaces.iter().filter(|iface| iface.is_default)) {
        push_alias(&mut aliases, "lan", iface, ip);
    }
    if let Some((iface, ip)) = first_ip(
        interfaces.iter().filter(|iface| iface.ips.iter().any(is_tailscale_ip)),
        Some(is_tailscale_ip),
    ) {
        push_alias(&mut aliases, "tailscale", iface, ip);
    }
    if let Some((iface, ip)) = first_ip(
        interfaces.iter().filter(|iface| matches!(iface.name.as_str(), "docker0" | "bridge100")),
        None,
    ) {
        push_alias(&mut aliases, "docker", iface, ip);
    }
    for interface in interfaces {
        if let Some(ip) = preferred_ip(&interface.ips) {
            push_alias(&mut aliases, &interface.name, &interface.name, ip);
        }
    }
    aliases
}

fn first_ipv4<'a>(
    mut interfaces: impl Iterator<Item = &'a InterfaceInfo>,
) -> Option<(&'a str, IpAddr)> {
    interfaces.find_map(|iface| {
        iface.ips.iter().copied().find(IpAddr::is_ipv4).map(|ip| (iface.name.as_str(), ip))
    })
}

fn first_ip<'a>(
    mut interfaces: impl Iterator<Item = &'a InterfaceInfo>,
    predicate: Option<fn(&IpAddr) -> bool>,
) -> Option<(&'a str, IpAddr)> {
    interfaces.find_map(|iface| {
        iface
            .ips
            .iter()
            .copied()
            .find(|ip| predicate.is_none_or(|predicate| predicate(ip)))
            .map(|ip| (iface.name.as_str(), ip))
    })
}

fn preferred_ip(ips: &[IpAddr]) -> Option<IpAddr> {
    ips.iter().copied().find(std::net::IpAddr::is_ipv4).or_else(|| ips.first().copied())
}

fn push_alias(aliases: &mut Vec<IfaceAlias>, alias: &str, iface: &str, ip: IpAddr) {
    if !aliases.iter().any(|existing| existing.alias == alias) {
        aliases.push(IfaceAlias { alias: alias.to_owned(), iface: iface.to_owned(), ip });
    }
}

fn is_tailscale_ip(ip: &IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn system_interfaces() -> Vec<InterfaceInfo> {
    let default_name = netdev::get_default_interface().ok().map(|iface| iface.name);
    let mut interfaces = BTreeMap::<String, Vec<IpAddr>>::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = interface.ip();
        interfaces.entry(interface.name).or_default().push(ip);
    }
    interfaces
        .into_iter()
        .map(|(name, ips)| InterfaceInfo {
            is_default: default_name.as_deref() == Some(name.as_str()),
            name,
            ips,
        })
        .collect()
}

#[cfg(test)]
#[path = "ifaces_tests.rs"]
mod tests;
