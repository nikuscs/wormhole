//! Non-privileged setup notices for local endpoint output.

use wormhole_core::{ActiveEndpoint, ClientConfig, EndpointSpec};

#[derive(Default)]
pub struct LocalNotices {
    pub hints: Vec<String>,
    pub warnings: Vec<String>,
}

const MDNS_WARNING: &str =
    ".local conflicts with mDNS/Bonjour (RFC 6762); use .test for custom local DNS";

pub fn detect(
    specs: &[EndpointSpec],
    tld_override: Option<&str>,
    config: &ClientConfig,
    managed_hosts: &[String],
) -> LocalNotices {
    let Some(hostname) =
        specs.iter().find(|spec| spec.driver == "local").and_then(|spec| spec.host.as_deref())
    else {
        return LocalNotices::default();
    };
    notices_for(hostname, tld_override.unwrap_or(&config.defaults.local_tld), managed_hosts)
}

fn notices_for(hostname: &str, tld: &str, managed_hosts: &[String]) -> LocalNotices {
    let mut notices = LocalNotices::default();
    if tld != "localhost" && !managed_hosts.iter().any(|managed| managed == hostname) {
        notices.hints.push(format!("wormhole local hosts sync {hostname}"));
    }
    if tld == "local" {
        notices.warnings.push(MDNS_WARNING.to_owned());
    }
    notices
}

/// Recomputes notices for endpoints already running, whose specs are no longer in hand.
///
/// `wormhole ls` reads live daemon state, so the suffix is taken from each hostname rather than
/// from current configuration, which may have changed since the endpoint started.
pub fn annotate_active(endpoints: &mut [ActiveEndpoint], managed_hosts: &[String]) {
    for endpoint in endpoints.iter_mut().filter(|endpoint| endpoint.driver == "local") {
        let Some(hostname) = endpoint.urls.iter().find_map(|url| url_hostname(url)) else {
            continue;
        };
        let tld = hostname.rsplit('.').next().unwrap_or_default().to_owned();
        let notices = notices_for(&hostname, &tld, managed_hosts);
        endpoint.hints = notices.hints;
        endpoint.warnings = notices.warnings;
    }
}

fn url_hostname(url: &str) -> Option<String> {
    let authority = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or_default();
    let host = authority.rsplit_once(':').map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub fn read_managed_hosts() -> Vec<String> {
    std::fs::read_to_string("/etc/hosts")
        .map(|contents| wormhole_core::local_system::managed_hosts(&contents))
        .unwrap_or_default()
}

pub fn apply(endpoints: &mut [ActiveEndpoint], notices: &LocalNotices) {
    for endpoint in endpoints.iter_mut().filter(|endpoint| endpoint.driver == "local") {
        endpoint.hints.clone_from(&notices.hints);
        endpoint.warnings.clone_from(&notices.warnings);
    }
}

#[cfg(test)]
#[path = "local_notices_tests.rs"]
mod tests;
