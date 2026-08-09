//! Non-privileged setup notices for local endpoint output.

use wormhole_core::{ActiveEndpoint, ClientConfig, EndpointSpec};

#[derive(Default)]
pub struct LocalNotices {
    pub hints: Vec<String>,
    pub warnings: Vec<String>,
}

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
    let tld = tld_override.unwrap_or(&config.defaults.local_tld);
    let mut notices = LocalNotices::default();
    if tld != "localhost" && !managed_hosts.iter().any(|managed| managed == hostname) {
        notices.hints.push(format!("wormhole local hosts sync {hostname}"));
    }
    if tld == "local" {
        notices.warnings.push(
            ".local conflicts with mDNS/Bonjour (RFC 6762); use .test for custom local DNS"
                .to_owned(),
        );
    }
    notices
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
