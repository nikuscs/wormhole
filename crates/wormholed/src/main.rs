//! Thin executable wrapper for the headless Wormhole relay server.
//! All relay behavior is implemented in the sibling library crate.

mod cli;
mod output;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            output::error(&error);
            ExitCode::FAILURE
        }
    }
}
