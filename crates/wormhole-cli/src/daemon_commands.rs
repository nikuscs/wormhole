//! Daemon operational log commands.

use std::time::Duration;

use crate::{error::CliError, output, runtime::RuntimePaths};

pub async fn logs(follow: bool) -> Result<(), CliError> {
    let paths = RuntimePaths::discover()?;
    let mut offset = 0_usize;
    loop {
        let content = tokio::fs::read(&paths.log).await.unwrap_or_default();
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
