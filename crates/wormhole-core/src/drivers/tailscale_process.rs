//! Tailscale process installation and monitoring helpers.

use std::{path::PathBuf, sync::Arc};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    driver::DriverEvent,
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget},
};

use super::{
    process::{ManagedProcess, ProcessSpec},
    tailscale::{CommandResult, TailscaleApi},
    tailscale_state::{binding_snapshot, record_ownership, remove_install, serve_status},
};

pub async fn record_installed_ownership(
    directory: Option<&std::path::Path>,
    api: &Arc<dyn TailscaleApi>,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> Result<(), DriverError> {
    let Some(directory) = directory else {
        return Ok(());
    };
    if let Err(error) = record_ownership(directory, mode, spec, target) {
        if let Err(cleanup) = remove_install(api, mode, spec, target).await {
            return Err(DriverError::Transport(format!(
                "{error}; tailscale cleanup failed: {cleanup}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

pub async fn cleanup_failed_install(
    api: &Arc<dyn TailscaleApi>,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
    error: &DriverError,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<(), DriverError> {
    if let Err(cleanup) = remove_install(api, mode, spec, target).await {
        return Err(DriverError::Transport(format!(
            "{error}; tailscale cleanup failed: {cleanup}"
        )));
    }
    let _log = events.send(DriverEvent::Log(tracing::Level::WARN, error.to_string())).await;
    Ok(())
}

pub async fn preview_install(
    events: &mpsc::Sender<DriverEvent>,
    command: &[String],
) -> Result<(), DriverError> {
    events
        .send(DriverEvent::Log(
            tracing::Level::INFO,
            format!("tailscale plan: {}", command.join(" ")),
        ))
        .await
        .map_err(|_| DriverError::Cancelled)
}

pub async fn install_endpoint(
    api: &Arc<dyn TailscaleApi>,
    binary: Option<&PathBuf>,
    command: &[String],
    background: bool,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<Option<ManagedProcess>, DriverError> {
    if let Some(binary) = binary.filter(|_| !background) {
        let process = ManagedProcess::spawn(&ProcessSpec::new(binary.clone(), command.to_vec()))?;
        if let Some(mut stderr) = process.take_stderr().await {
            let events = events.clone();
            tokio::spawn(async move {
                while let Some(line) = stderr.recv().await {
                    if events.send(DriverEvent::Log(tracing::Level::DEBUG, line)).await.is_err() {
                        break;
                    }
                }
            });
        }
        Ok(Some(process))
    } else {
        let installed = api.command(command).await?;
        require_success(&installed, "tailscale serve/funnel")?;
        Ok(None)
    }
}

pub async fn monitor_install(
    api: &Arc<dyn TailscaleApi>,
    process: Option<&ManagedProcess>,
    spec: &EndpointSpec,
    target: ResolvedTarget,
    installed: &CommandResult,
    stop: &CancellationToken,
) -> Result<bool, DriverError> {
    if let Some(process) = process {
        return tokio::select! {
            () = stop.cancelled() => Ok(true),
            result = process.wait() => result.map(|_| false),
        };
    }
    loop {
        tokio::select! {
            () = stop.cancelled() => return Ok(true),
            () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                let Ok(current) = serve_status(api).await else {
                    continue;
                };
                let expected = binding_snapshot(&installed.stdout, spec, target);
                let observed = binding_snapshot(&current.stdout, spec, target);
                if !current.success || observed != expected {
                    return Ok(false);
                }
            }
        }
    }
}

fn require_success(result: &CommandResult, action: &str) -> Result<(), DriverError> {
    if result.success {
        Ok(())
    } else {
        Err(DriverError::Transport(format!("{action} failed: {}", result.stderr.trim())))
    }
}
