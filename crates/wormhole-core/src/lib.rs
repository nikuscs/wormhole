//! Wormhole client engine, driver registry, and tunnel lifecycle management.

pub mod config;
pub mod doctor;
pub mod driver;
pub mod drivers;
pub mod error;
pub mod ifaces;
pub mod keys_store;
pub mod manager;
mod manager_status;
pub mod model;
pub mod ports;
pub mod remotes;
mod wormhole_conn;
pub mod wormhole_driver;
mod wormhole_stream;
mod wormhole_transport;

pub use config::ClientConfig;
pub use doctor::doctor;
pub use driver::{DriverEvent, DriverHealth, DriverRegistry, EndpointEvent, TunnelDriver};
pub use error::{ConfigError, DriverError, IdentityError, IfaceError, ManagerError, PortError};
pub use manager::TunnelManager;
pub use model::{ActiveEndpoint, EndpointSpec, ResolvedTarget, Service, Target};
pub use remotes::Remote;
