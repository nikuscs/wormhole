//! Self-hosted Wormhole relay server library.
//! The relay accepts authenticated tunnel sessions and routes public HTTP and TCP traffic.

pub mod authz;
pub mod config;
pub mod db;
mod db_models;
pub mod registry;
mod registry_types;
