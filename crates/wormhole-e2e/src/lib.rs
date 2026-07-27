//! End-to-end harness for exercising Wormhole binaries over real local sockets.
//! Integration tests spawn complete client and relay processes.

pub mod harness;

#[cfg(test)]
#[path = "smoke_tests.rs"]
mod tests;
