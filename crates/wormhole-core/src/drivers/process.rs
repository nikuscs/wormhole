//! Shared provider child-process supervision.

use std::{
    collections::BTreeMap, os::unix::process::CommandExt as _, path::PathBuf, process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::{Child, Command},
    sync::{Mutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{driver::DriverEvent, error::DriverError};

const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Reusable child command definition.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

impl ProcessSpec {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self { program: program.into(), args, env: BTreeMap::new() }
    }
}

/// One process group that is terminated when dropped.
pub struct ManagedProcess {
    child: Mutex<Option<Child>>,
    pid: i32,
    stderr: Mutex<Option<mpsc::Receiver<String>>>,
}

impl ManagedProcess {
    pub fn spawn(spec: &ProcessSpec) -> Result<Self, DriverError> {
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .envs(&spec.env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().map_err(|error| {
            DriverError::Transport(format!("cannot start {}: {error}", spec.program.display()))
        })?;
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or_else(|| DriverError::Transport("provider child has no process id".to_owned()))?;
        let (stderr_tx, stderr_rx) = mpsc::channel(128);
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if stderr_tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }
        Ok(Self { child: Mutex::new(Some(child)), pid, stderr: Mutex::new(Some(stderr_rx)) })
    }

    pub async fn take_stderr(&self) -> Option<mpsc::Receiver<String>> {
        self.stderr.lock().await.take()
    }

    pub async fn wait(&self) -> Result<std::process::ExitStatus, DriverError> {
        let mut guard = self.child.lock().await;
        let result = guard
            .as_mut()
            .ok_or_else(|| DriverError::Transport("provider child already reaped".to_owned()))?
            .wait()
            .await
            .map_err(|error| DriverError::Transport(error.to_string()));
        drop(guard);
        result
    }

    pub async fn terminate(&self) -> Result<(), DriverError> {
        terminate_group(self.pid, nix::sys::signal::Signal::SIGTERM);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let exited = {
                let mut child = self.child.lock().await;
                child.as_mut().is_none_or(|child| child.try_wait().ok().flatten().is_some())
            };
            if exited || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if process_group_alive(self.pid) {
            terminate_group(self.pid, nix::sys::signal::Signal::SIGKILL);
        }
        if let Some(child) = self.child.lock().await.as_mut() {
            let _status = child.wait().await;
        }
        Ok(())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        terminate_group(self.pid, nix::sys::signal::Signal::SIGKILL);
    }
}

pub fn forward_logs(receiver: Option<mpsc::Receiver<String>>, events: mpsc::Sender<DriverEvent>) {
    if let Some(mut receiver) = receiver {
        tokio::spawn(async move {
            while let Some(line) = receiver.recv().await {
                if events.send(DriverEvent::Log(tracing::Level::DEBUG, line)).await.is_err() {
                    break;
                }
            }
        });
    }
}

pub async fn wait_healthy<F, Fut>(timeout: Duration, mut probe: F) -> Result<(), DriverError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if probe().await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(DriverError::Transport("provider health probe timed out".to_owned()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn run_restarting<F, Fut>(
    spec: ProcessSpec,
    stop: CancellationToken,
    mut healthy: F,
) -> Result<(), DriverError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut backoff = INITIAL_BACKOFF;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let process = ManagedProcess::spawn(&spec)?;
        let health = tokio::select! {
            () = stop.cancelled() => {
                process.terminate().await?;
                return Ok(());
            }
            result = wait_healthy(Duration::from_secs(10), &mut healthy) => result,
            result = process.wait() => {
                result?;
                Err(DriverError::Transport("provider exited before becoming healthy".to_owned()))
            }
        };
        if health.is_ok() {
            backoff = INITIAL_BACKOFF;
            tokio::select! {
                () = stop.cancelled() => {
                    process.terminate().await?;
                    return Ok(());
                }
                result = process.wait() => {
                    result?;
                }
            }
        }
        process.terminate().await?;
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

fn terminate_group(pid: i32, signal: nix::sys::signal::Signal) {
    let _sent = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal);
}

fn process_group_alive(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(-pid), None).is_ok()
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
