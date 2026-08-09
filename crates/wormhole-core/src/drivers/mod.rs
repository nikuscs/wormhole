//! External provider drivers and registry construction.

pub mod cloudflare;
mod cloudflare_command;
mod cloudflare_metrics;
mod cloudflare_named;
pub mod local;
pub mod process;
pub mod tailscale;
mod tailscale_args;
mod tailscale_ports;
mod tailscale_process;
mod tailscale_state;

#[cfg(test)]
mod conformance;

use std::sync::Arc;

use crate::{
    config::{ClientConfig, global_config_path},
    driver::DriverRegistry,
    keys_store::IdentityStore,
    wormhole_driver::WormholeDriver,
};

/// Builds the production driver registry from effective client configuration.
pub fn build_registry(config: &ClientConfig, identities: Arc<IdentityStore>) -> DriverRegistry {
    let registry = DriverRegistry::new();
    registry.register(Arc::new(WormholeDriver::new(
        config.remotes.clone(),
        config.default_remote.clone(),
        identities,
    )));
    registry.register(Arc::new(tailscale::TailscaleDriver::system(
        config.defaults.tailscale_https_port_range,
    )));
    registry.register(Arc::new(cloudflare::CloudflareDriver::system()));
    let ca_directory =
        global_config_path().ok().and_then(|path| path.parent().map(camino::Utf8Path::to_owned));
    registry.register(Arc::new(local::LocalDriver::new(
        config.defaults.local_http_port,
        config.defaults.local_https_port,
        ca_directory,
    )));
    registry
}
