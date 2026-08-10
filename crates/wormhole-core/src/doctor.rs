//! Structured client diagnostics for configuration, identity, remotes, and drivers.

use std::sync::Arc;

use crate::{
    config::{ClientConfig, ConfigLayer},
    driver::{DriverHealth, DriverRegistry},
    drivers::build_registry,
    keys_store::IdentityStore,
    model::DoctorCheck,
    remotes::Transport,
    wormhole_connect::probe_remote,
};

/// Runs diagnostics using environment configuration and the built-in Wormhole driver.
pub async fn doctor() -> Vec<DoctorCheck> {
    let config = match ClientConfig::load(None, ConfigLayer::default()) {
        Ok(config) => config,
        Err(error) => {
            return vec![DoctorCheck {
                name: "config".to_owned(),
                healthy: false,
                detail: error.to_string(),
            }];
        }
    };
    let identities = match IdentityStore::from_environment() {
        Ok(store) => Arc::new(store),
        Err(error) => {
            return vec![
                DoctorCheck {
                    name: "config".to_owned(),
                    healthy: true,
                    detail: "loaded".to_owned(),
                },
                DoctorCheck {
                    name: "identity".to_owned(),
                    healthy: false,
                    detail: error.to_string(),
                },
            ];
        }
    };
    let registry = build_registry(&config, Arc::clone(&identities), None);
    doctor_with(&config, &registry, &identities).await
}

/// Runs diagnostics against injected effective state.
pub async fn doctor_with(
    config: &ClientConfig,
    registry: &DriverRegistry,
    identities: &IdentityStore,
) -> Vec<DoctorCheck> {
    let mut checks = vec![DoctorCheck {
        name: "config".to_owned(),
        healthy: config.validate().is_ok(),
        detail: config.validate().map_or_else(|error| error.to_string(), |()| "valid".to_owned()),
    }];
    checks.push(identity_check("identity", identities.default_path()));
    for (name, remote) in &config.remotes {
        if remote.identity.is_some() {
            let path = identities.path_for_remote(remote);
            checks.push(identity_check(&format!("identity:{name}"), &path));
        }
        let result = identities.resolve_identity(remote).map_err(|error| error.to_string());
        let result = match result {
            Ok(identity) => tokio::time::timeout(
                std::time::Duration::from_secs(8),
                probe_remote(remote, &identity),
            )
            .await
            .map_err(|_| "configured transport probe timed out".to_owned())
            .and_then(|result| result.map_err(|error| error.to_string())),
            Err(error) => Err(error),
        };
        checks.push(DoctorCheck {
            name: format!("remote:{name}"),
            healthy: result.is_ok(),
            detail: result.map_or_else(|error| error, transport_detail),
        });
    }
    for driver in registry.all() {
        for (name, health) in driver.diagnostics().await {
            checks.push(DoctorCheck {
                name: format!("driver:{name}"),
                healthy: health == DriverHealth::Healthy,
                detail: match health {
                    DriverHealth::Healthy => "ready".to_owned(),
                    DriverHealth::Degraded(reason) | DriverHealth::Unavailable(reason) => reason,
                },
            });
        }
    }
    checks
}

fn transport_detail(transport: Transport) -> String {
    match transport {
        Transport::Quic => "QUIC/TLS reachable".to_owned(),
        Transport::Ws => "WebSocket/TLS reachable".to_owned(),
        Transport::Auto => unreachable!("transport probe resolves auto mode"),
    }
}

fn identity_check(name: &str, path: &camino::Utf8Path) -> DoctorCheck {
    let result = wormhole_proto::Identity::load(path);
    DoctorCheck {
        name: name.to_owned(),
        healthy: result.is_ok(),
        detail: result.map_or_else(|error| error.to_string(), |_| path.to_string()),
    }
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
