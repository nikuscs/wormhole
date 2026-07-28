//! Daemon operational log commands.

use std::{io, time::Duration};

use crate::{error::CliError, output, runtime::RuntimePaths};

pub async fn logs(follow: bool) -> Result<(), CliError> {
    let paths = RuntimePaths::discover()?;
    let mut offset = 0_usize;
    loop {
        let content = read_log(&paths.log).await?;
        if content.len() < offset {
            offset = 0;
        }
        if content.len() > offset {
            output::emit_raw(&content[offset..])?;
            offset = content.len();
        }
        if !follow {
            return Ok(());
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => return result.map_err(Into::into),
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

async fn read_log(path: &camino::Utf8Path) -> Result<Vec<u8>, io::Error> {
    match tokio::fs::read(path).await {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "daemon_commands_tests.rs"]
mod tests;
