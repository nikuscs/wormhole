//! All terminal output. The only module allowed to print.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use serde::Serialize;

/// Selects human-readable or machine-readable command output.
pub enum Format {
    /// Render concise text for terminal users.
    Human,
    /// Render pretty-printed JSON for tools and agents.
    Json,
}

/// Emits a serializable value using the requested output format.
pub fn emit<T: Serialize + HumanRender>(format: Format, value: &T) {
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(value).expect("value must serialize"));
        }
        Format::Human => println!("{}", value.render()),
    }
}

/// Supplies the human-readable representation of command output.
pub trait HumanRender {
    /// Renders a value for terminal users.
    fn render(&self) -> String;
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
