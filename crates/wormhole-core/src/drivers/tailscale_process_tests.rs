use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use super::{
    cleanup_failed_install, install_endpoint, monitor_install, preview_install,
    record_installed_ownership,
};
use crate::{
    driver::DriverEvent,
    drivers::tailscale::{CommandResult, TailscaleApi},
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

struct Api {
    success: bool,
}

#[async_trait]
impl TailscaleApi for Api {
    async fn command(&self, _args: &[String]) -> Result<CommandResult, DriverError> {
        Ok(CommandResult {
            success: self.success,
            stdout: String::new(),
            stderr: "failed".to_owned(),
        })
    }
    fn available(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn command_install_preview_and_cancelled_monitor_are_bounded() {
    let api: Arc<dyn TailscaleApi> = Arc::new(Api { success: true });
    let (events, mut received) = mpsc::channel(4);
    let command = vec!["serve".to_owned(), "--bg".to_owned()];
    preview_install(&events, &command).await.expect("preview");
    assert!(matches!(received.recv().await, Some(DriverEvent::Log(_, _))));
    assert!(
        install_endpoint(&api, None, &command, true, &events).await.expect("install").is_none()
    );
    record_installed_ownership(None, &api, "serve", &spec(), target())
        .await
        .expect("no state directory");
    let stop = CancellationToken::new();
    stop.cancel();
    assert!(
        monitor_install(
            &api,
            None,
            &spec(),
            target(),
            &CommandResult { success: true, stdout: String::new(), stderr: String::new() },
            &stop,
        )
        .await
        .expect("monitor")
    );
}

#[tokio::test]
async fn foreground_install_forwards_stderr_and_stops_monitoring() {
    let api: Arc<dyn TailscaleApi> = Arc::new(Api { success: true });
    let (events, mut received) = mpsc::channel(4);
    let binary = std::path::PathBuf::from("/bin/sh");
    let command = vec!["-c".to_owned(), "echo provider-log >&2; sleep 10".to_owned()];
    let process = install_endpoint(&api, Some(&binary), &command, false, &events)
        .await
        .expect("install")
        .expect("process");
    assert!(
        matches!(received.recv().await, Some(DriverEvent::Log(_, message)) if message == "provider-log")
    );
    let stop = CancellationToken::new();
    stop.cancel();
    assert!(
        monitor_install(
            &api,
            Some(&process),
            &spec(),
            target(),
            &CommandResult { success: true, stdout: String::new(), stderr: String::new() },
            &stop,
        )
        .await
        .expect("monitor")
    );
    process.terminate().await.expect("terminate");
}

#[tokio::test]
async fn failed_install_cleanup_emits_original_error() {
    let api: Arc<dyn TailscaleApi> = Arc::new(Api { success: true });
    let (events, mut received) = mpsc::channel(4);
    cleanup_failed_install(
        &api,
        "serve",
        &spec(),
        target(),
        &DriverError::Transport("install failed".to_owned()),
        &events,
    )
    .await
    .expect("cleanup");
    assert!(
        matches!(received.recv().await, Some(DriverEvent::Log(_, message)) if message.contains("install failed"))
    );
}

#[tokio::test]
async fn failed_command_and_closed_preview_channel_surface_errors() {
    let api: Arc<dyn TailscaleApi> = Arc::new(Api { success: false });
    let (events, receiver) = mpsc::channel(1);
    drop(receiver);
    assert!(matches!(preview_install(&events, &[],).await, Err(DriverError::Cancelled)));
    assert!(matches!(
        install_endpoint(&api, None, &[], true, &events).await,
        Err(DriverError::Transport(_))
    ));
}

fn target() -> ResolvedTarget {
    ResolvedTarget("127.0.0.1:3000".parse().expect("target"))
}

fn spec() -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "tailscale".to_owned(),
        qualifier: Some("serve".to_owned()),
        remote: None,
        host: None,
        auto_host: false,
        domain: None,
        public_port: None,
        persist: Persistence::Temporary,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 1024,
        reservation: None,
    }
}
