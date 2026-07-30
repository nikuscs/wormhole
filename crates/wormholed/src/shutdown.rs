//! Unix signal handling and bounded graceful relay shutdown.

use std::{future::Future, sync::Arc, time::Duration};

use crate::{certs::CertManager, quic::QuicServer, state::AppState};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits for SIGINT or SIGTERM.
pub async fn wait_for_termination() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        select_termination(tokio::signal::ctrl_c(), async move {
            let _signal = terminate.recv().await;
        })
        .await
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

/// Reloads static certificates whenever SIGHUP is received.
pub fn spawn_certificate_reload(certificates: Arc<CertManager>) {
    #[cfg(unix)]
    tokio::spawn(async move {
        let Ok(mut hangup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while hangup.recv().await.is_some() {
            if let Err(error) = certificates.reload_static() {
                tracing::warn!(%error, "certificate reload failed");
            } else {
                tracing::info!("certificates reloaded");
            }
        }
    });
}

#[cfg(unix)]
async fn select_termination<C, T>(ctrl_c: C, terminate: T) -> std::io::Result<()>
where
    C: Future<Output = std::io::Result<()>>,
    T: Future<Output = ()>,
{
    tokio::select! {
        result = ctrl_c => result,
        () = terminate => Ok(()),
    }
}

/// Notifies sessions, waits up to 30 seconds, then closes the QUIC endpoint.
pub async fn drain(state: &AppState, server: &QuicServer) {
    wait_for_drain(state, DRAIN_TIMEOUT).await;
    server.endpoint().close(0_u32.into(), b"shutdown");
}

async fn wait_for_drain(state: &AppState, timeout: Duration) {
    state.begin_shutdown();
    let deadline = tokio::time::Instant::now() + timeout;
    while (state.totals().0 > 0 || state.active_streams() > 0)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod tests;
