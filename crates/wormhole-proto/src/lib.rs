//! Wire types, codecs, identity, and handshake primitives shared by Wormhole peers.
//! This crate remains transport-independent so protocol behavior is easy to test.

pub mod codec;
pub mod error;
pub mod frames;
pub mod handshake;
pub mod keys;
pub mod mux;
pub mod mux_runtime;
mod mux_runtime_actor;
mod mux_runtime_control;
mod mux_runtime_io;
mod mux_runtime_types;

pub use error::ProtoError;
pub use frames::{ALPN, PROTO_VERSION};
pub use handshake::{ClientHandshake, HandshakeStep, KeyDecision, ServerHandshake, Welcome};
pub use keys::{Identity, PublicKeyRef, verify_challenge};

#[cfg(test)]
#[path = "property_tests.rs"]
mod property_tests;
