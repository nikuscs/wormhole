//! Thin executable wrapper for the headless Wormhole relay server.
//! All relay behavior is implemented in the sibling library crate.

mod cli;
mod output;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            output::error(&error);
            ExitCode::FAILURE
        }
    }
}
