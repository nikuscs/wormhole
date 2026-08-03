//! Cloudflare process lifecycle and named-tunnel DNS readiness helpers.

use std::{path::PathBuf, time::Duration};

use rand::RngExt as _;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{CloudflareDriver, INITIAL_BACKOFF, INSTALL_HINT, MAX_BACKOFF, NAMED_DNS_TIMEOUT};
use crate::{
    driver::DriverEvent,
    drivers::{
        cloudflare_metrics::{discover_quick_url, ready},
        process::{ManagedProcess, ProcessSpec, forward_logs, wait_healthy},
    },
    error::DriverError,
    model::ResolvedTarget,
    ports::reserve_port,
};

impl CloudflareDriver {
    pub(super) async fn run_quick(
        &self,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let binary =
            self.binary.clone().ok_or_else(|| DriverError::Unavailable(INSTALL_HINT.to_owned()))?;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            match start_quick(binary.clone(), target, &events).await {
                Ok((process, url)) => {
                    backoff = INITIAL_BACKOFF;
                    events
                        .send(DriverEvent::Ready {
                            urls: vec![url],
                            bind_id: None,
                            reservation: None,
                        })
                        .await
                        .map_err(|_| DriverError::Cancelled)?;
                    tokio::select! {
                        () = stop.cancelled() => {
                            process.terminate().await?;
                            let _closed = events.send(DriverEvent::Closed).await;
                            return Ok(());
                        }
                        result = process.wait() => {
                            let _status = result?;
                        }
                    }
                }
                Err(error) => {
                    let _log = events
                        .send(DriverEvent::Log(tracing::Level::WARN, error.to_string()))
                        .await;
                }
            }
            let _status = events
                .send(DriverEvent::StatusChanged(crate::model::EndpointStatus::Reconnecting))
                .await;
            let jitter = rand::rng().random_range(0..=backoff.as_millis() as u64);
            tokio::select! {
                () = stop.cancelled() => {
                    let _closed = events.send(DriverEvent::Closed).await;
                    return Ok(());
                }
                () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }
}

#[derive(Debug)]
pub(super) struct NamedTunnel {
    pub(super) id: String,
    pub(super) created: bool,
}

pub(super) struct NamedRoute {
    pub(super) name: String,
    pub(super) tunnel_id: String,
}

pub(super) struct NamedConnector {
    pub(super) binary: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) metrics_port: u16,
    pub(super) config_path: PathBuf,
    pub(super) url: String,
}

pub(super) async fn announce_named_plan(
    events: &mpsc::Sender<DriverEvent>,
    name: &str,
    host: &str,
    target: ResolvedTarget,
    owned: bool,
) -> Result<(), DriverError> {
    let overwrite = if owned { " --overwrite-dns" } else { "" };
    events
        .send(DriverEvent::Log(
            tracing::Level::INFO,
            format!(
                "cloudflared plan: tunnel create {name}; tunnel route dns{overwrite} {name} {host}; service=http://{}; catch-all=http_status:404",
                target.0
            ),
        ))
        .await
        .map_err(|_| DriverError::Cancelled)
}

pub(super) fn named_run_args(name: &str, config_path: &std::path::Path) -> Vec<String> {
    vec![
        "tunnel".to_owned(),
        "--no-autoupdate".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--config".to_owned(),
        config_path.to_string_lossy().into_owned(),
        "run".to_owned(),
        name.to_owned(),
    ]
}

pub(super) fn named_authoritative_dns_error(host: &str) -> DriverError {
    DriverError::Capability(format!(
        "Cloudflare named tunnel hostname {host} is not under Cloudflare-authoritative DNS"
    ))
}

pub(super) fn named_dns_error(host: &str) -> DriverError {
    DriverError::Transport(format!(
        "Cloudflare named tunnel hostname {host} is not publicly resolvable after route creation"
    ))
}

pub(super) async fn cloudflare_authoritative_dns(host: &str) -> bool {
    let Some(client) = dns_client() else {
        return false;
    };
    let labels = host.split('.').collect::<Vec<_>>();
    for offset in 0..labels.len().saturating_sub(1) {
        let candidate = labels[offset..].join(".");
        let Some(response) = dns_query(&client, &candidate, "NS").await else {
            continue;
        };
        let nameservers = dns_answers(&response, 2);
        if !nameservers.is_empty() {
            return nameservers
                .iter()
                .all(|name| name.trim_end_matches('.').ends_with(".ns.cloudflare.com"));
        }
    }
    false
}

pub(super) async fn public_dns_ready(host: String) -> bool {
    let Some(client) = dns_client() else {
        return false;
    };
    let deadline = tokio::time::Instant::now() + NAMED_DNS_TIMEOUT;
    loop {
        if dns_query(&client, &host, "A")
            .await
            .is_some_and(|response| !dns_answers(&response, 1).is_empty())
        {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn dns_client() -> Option<reqwest::Client> {
    reqwest::Client::builder().timeout(Duration::from_secs(3)).build().ok()
}

async fn dns_query(client: &reqwest::Client, name: &str, record_type: &str) -> Option<Value> {
    client
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", name), ("type", record_type)])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

fn dns_answers(value: &Value, record_type: u64) -> Vec<&str> {
    value
        .get("Answer")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|answer| answer.get("type").and_then(Value::as_u64) == Some(record_type))
        .filter_map(|answer| answer.get("data").and_then(Value::as_str))
        .collect()
}

async fn start_quick(
    binary: PathBuf,
    target: ResolvedTarget,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<(ManagedProcess, String), DriverError> {
    let (metrics_port, reservation) =
        reserve_port(20_000..=29_999).map_err(|error| DriverError::Transport(error.to_string()))?;
    let args = vec![
        "tunnel".to_owned(),
        "--no-autoupdate".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--url".to_owned(),
        format!("http://{}", target.0),
        "--metrics".to_owned(),
        format!("127.0.0.1:{metrics_port}"),
    ];
    drop(reservation);
    let process = ManagedProcess::spawn(&ProcessSpec::new(binary, args))?;
    let mut stderr = process.take_stderr().await;
    let url = discover_quick_url(metrics_port, &mut stderr, events).await?;
    wait_healthy(Duration::from_secs(10), || ready(metrics_port)).await?;
    forward_logs(stderr, events.clone());
    Ok((process, url))
}

pub(super) async fn start_named(
    binary: PathBuf,
    args: Vec<String>,
    metrics_port: u16,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<ManagedProcess, DriverError> {
    let process = ManagedProcess::spawn(&ProcessSpec::new(binary, args))?;
    forward_logs(process.take_stderr().await, events.clone());
    if let Err(error) = wait_healthy(Duration::from_secs(10), || ready(metrics_port)).await {
        process.terminate().await?;
        return Err(error);
    }
    Ok(process)
}
