//! Wire types, codecs, identity, and handshake primitives shared by Wormhole peers.
//! This crate remains transport-independent so protocol behavior is easy to test.

#[cfg(not(target_arch = "wasm32"))]
pub mod codec;
pub mod error;
pub mod frames;
#[cfg(not(target_arch = "wasm32"))]
pub mod handshake;
mod key_verify;
#[cfg(not(target_arch = "wasm32"))]
pub mod keys;
pub mod mux;
#[cfg(not(target_arch = "wasm32"))]
pub mod mux_runtime;
#[cfg(not(target_arch = "wasm32"))]
mod mux_runtime_actor;
#[cfg(not(target_arch = "wasm32"))]
mod mux_runtime_control;
#[cfg(not(target_arch = "wasm32"))]
mod mux_runtime_io;
#[cfg(not(target_arch = "wasm32"))]
mod mux_runtime_types;

pub use error::ProtoError;
pub use frames::{ALPN, PROTO_VERSION};
#[cfg(not(target_arch = "wasm32"))]
pub use handshake::{ClientHandshake, HandshakeStep, KeyDecision, ServerHandshake, Welcome};
pub use key_verify::{PublicKeyRef, verify_challenge};
#[cfg(not(target_arch = "wasm32"))]
pub use keys::Identity;

#[cfg(test)]
#[path = "property_tests.rs"]
mod property_tests;
