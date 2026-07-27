//! Self-hosted Wormhole relay server library.
//! The relay accepts authenticated tunnel sessions and routes public HTTP and TCP traffic.

pub mod acme;
mod acme_cloudflare;
pub mod admin;
pub mod admin_client;
pub mod authz;
pub mod certs;
pub mod config;
pub mod db;
mod db_models;
mod edge_auth;
pub mod edge_http;
pub mod edge_https;
pub mod edge_tcp;
mod edge_types;
pub mod quic;
pub mod registry;
mod registry_types;
pub mod session;
mod session_streams;
pub mod shutdown;
pub mod state;
