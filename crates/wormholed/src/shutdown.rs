//! Unix signal handling and bounded graceful relay shutdown.

use std::{sync::Arc, time::Duration};

use crate::{certs::CertManager, quic::QuicServer, state::AppState};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits for SIGINT or SIGTERM.
pub async fn wait_for_termination() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
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

/// Notifies sessions, waits up to 30 seconds, then closes the QUIC endpoint.
pub async fn drain(state: &AppState, server: &QuicServer) {
    state.begin_shutdown();
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while (state.totals().0 > 0 || state.active_streams() > 0)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server.endpoint().close(0_u32.into(), b"shutdown");
}
