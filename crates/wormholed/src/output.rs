//! Terminal output for the relay CLI. The only relay module allowed to print.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use serde::Serialize;

pub fn human(message: &str) {
    println!("{message}");
}

pub fn json<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn error(error: &anyhow::Error) {
    eprintln!("error: {error:#}");
}
