//! Shared cloudflared command discovery and result helpers.

use std::path::PathBuf;

use crate::{driver::DriverHealth, error::DriverError};

pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn command_error(action: &str, output: &CommandOutput) -> DriverError {
    DriverError::Transport(format!("{action} failed: {}", output.stderr.trim()))
}

pub fn ensure_healthy(health: DriverHealth) -> Result<(), DriverError> {
    match health {
        DriverHealth::Healthy => Ok(()),
        DriverHealth::Degraded(message) | DriverHealth::Unavailable(message) => {
            Err(DriverError::Unavailable(message))
        }
    }
}

pub fn discover_cloudflared() -> Option<PathBuf> {
    std::env::var_os("WORMHOLE_CLOUDFLARED_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| discover_on_path("cloudflared"))
}

fn discover_on_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

pub fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}

pub fn strings3(first: &str, second: &str, third: &str) -> Vec<String> {
    vec![first.to_owned(), second.to_owned(), third.to_owned()]
}
