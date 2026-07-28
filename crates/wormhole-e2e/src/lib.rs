//! End-to-end harness for exercising Wormhole binaries over real local sockets.
//! Integration tests spawn complete client and relay processes.

pub mod harness;
mod helpers;
#[cfg(test)]
mod relay_control;
#[cfg(test)]
#[path = "security_tests.rs"]
mod security_tests;
#[cfg(test)]
mod semantics_server;
#[cfg(test)]
mod upload_server;

#[cfg(test)]
#[path = "smoke_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "matrix_tests.rs"]
mod matrix_tests;

#[cfg(test)]
#[path = "chaos_tests.rs"]
mod chaos_tests;

#[cfg(test)]
#[path = "load_tests.rs"]
mod load_tests;
