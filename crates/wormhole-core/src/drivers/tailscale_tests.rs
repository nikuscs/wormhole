use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    config::HttpsPortRange,
    driver::{DriverEvent, DriverHealth, TunnelDriver},
    model::{EndpointSpec, ServiceProto},
};

use super::{CommandResult, TailscaleApi, TailscaleDriver, install_args, public_url};

struct FakeApi {
    calls: Mutex<Vec<Vec<String>>>,
    installed: Mutex<Option<String>>,
}

#[async_trait]
impl TailscaleApi for FakeApi {
    async fn command(&self, args: &[String]) -> Result<CommandResult, crate::DriverError> {
        self.calls.lock().push(args.to_vec());
        let stdout = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            ["version"] => "1.80.0".to_owned(),
            ["status", "--json"] => include_str!("testdata/tailscale/status.json").to_owned(),
            ["serve", "status", "--json"] => self
                .installed
                .lock()
                .as_ref()
                .map_or_else(|| "{}".to_owned(), |target| format!("{{\"target\":{target:?}}}")),
            ["serve" | "funnel", "--bg", target] | ["serve" | "funnel", "--bg", _, target] => {
                *self.installed.lock() = Some((*target).to_owned());
                String::new()
            }
            ["serve" | "funnel", _, "off"] => {
                *self.installed.lock() = None;
                String::new()
            }
            _ => String::new(),
        };
        Ok(CommandResult { success: true, stdout, stderr: String::new() })
    }

    fn available(&self) -> bool {
        true
    }
}

struct PortConflictApi {
    calls: Mutex<Vec<Vec<String>>>,
    bindings: Mutex<BTreeMap<u16, String>>,
}

#[async_trait]
impl TailscaleApi for PortConflictApi {
    async fn command(&self, args: &[String]) -> Result<CommandResult, crate::DriverError> {
        self.calls.lock().push(args.to_vec());
        let values = args.iter().map(String::as_str).collect::<Vec<_>>();
        let stdout = match values.as_slice() {
            ["version"] => "1.80.0".to_owned(),
            ["status", "--json"] => include_str!("testdata/tailscale/status.json").to_owned(),
            ["serve", "status", "--json"] => self.status_json(),
            ["serve", "--bg", option, target] if option.starts_with("--https=") => {
                let port = option.trim_start_matches("--https=").parse().expect("HTTPS port");
                self.bindings.lock().insert(port, (*target).to_owned());
                String::new()
            }
            ["serve", option, "off"] if option.starts_with("--https=") => {
                let port = option.trim_start_matches("--https=").parse().expect("HTTPS port");
                self.bindings.lock().remove(&port);
                String::new()
            }
            _ => String::new(),
        };
        Ok(CommandResult { success: true, stdout, stderr: String::new() })
    }

    fn available(&self) -> bool {
        true
    }
}

impl PortConflictApi {
    fn new(bindings: impl IntoIterator<Item = (u16, &'static str)>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            bindings: Mutex::new(
                bindings.into_iter().map(|(port, target)| (port, target.to_owned())).collect(),
            ),
        }
    }

    fn status_json(&self) -> String {
        let web = self
            .bindings
            .lock()
            .iter()
            .map(|(port, target)| {
                (format!("node:{port}"), serde_json::json!({"Handlers": {"/": {"Proxy": target}}}))
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({"Web": web}).to_string()
    }
}

fn spec(qualifier: Option<&str>) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "tailscale".to_owned(),
        qualifier: qualifier.map(str::to_owned),
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
        capture_body_max: 1024 * 1024,
        reservation: None,
    }
}

#[tokio::test]
async fn fixture_driver_installs_reports_and_cleans_serve() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = Arc::new(TailscaleDriver::with_api(api.clone()));
    assert_eq!(driver.check().await, DriverHealth::Healthy);
    crate::drivers::conformance::assert_lifecycle(driver, spec(None), || async {
        api.installed.lock().is_none()
    })
    .await;
}

#[tokio::test]
async fn identical_preexisting_binding_is_not_claimed_or_removed() {
    let api = Arc::new(FakeApi {
        calls: Mutex::new(Vec::new()),
        installed: Mutex::new(Some("http://127.0.0.1:3000".to_owned())),
    });
    let driver = TailscaleDriver::with_api(api.clone());
    let (events, _receiver) = mpsc::channel(16);
    let error = driver
        .run(
            spec(None),
            crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
            events,
            CancellationToken::new(),
        )
        .await
        .expect_err("unowned binding must fail");
    assert!(matches!(error, crate::DriverError::Capability(_)));
    assert!(error.to_string().contains("public_port"));
    assert_eq!(api.installed.lock().as_deref(), Some("http://127.0.0.1:3000"));
    assert!(!api.calls.lock().iter().any(|args| args.last().is_some_and(|arg| arg == "off")));
}

#[tokio::test]
async fn automatic_port_conflict_retries_and_succeeds() {
    let api = Arc::new(PortConflictApi::new([(443, "http://127.0.0.1:9999")]));
    let driver = TailscaleDriver::with_api_and_range(
        api.clone(),
        HttpsPortRange { start: 21_000, end: 21_002 },
    );
    let (events_tx, mut events_rx) = mpsc::channel(16);
    let stop = CancellationToken::new();
    let run_stop = stop.clone();
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let task =
        tokio::spawn(async move { driver.run(spec(None), target, events_tx, run_stop).await });
    let urls = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(DriverEvent::Ready { urls, .. }) = events_rx.recv().await {
                break urls;
            }
        }
    })
    .await
    .expect("ready timeout");
    assert_eq!(urls, ["https://node.example.ts.net:21000"]);
    assert_eq!(api.bindings.lock().get(&443).map(String::as_str), Some("http://127.0.0.1:9999"));
    assert_eq!(api.bindings.lock().get(&21_000).map(String::as_str), Some("http://127.0.0.1:3000"));
    stop.cancel();
    task.await.expect("driver task").expect("clean shutdown");
    assert!(!api.bindings.lock().contains_key(&21_000));
    assert!(api.bindings.lock().contains_key(&443));
}

#[tokio::test]
async fn explicit_port_conflict_fails_without_changes() {
    let api = Arc::new(PortConflictApi::new([(21_000, "http://127.0.0.1:9999")]));
    let driver = TailscaleDriver::with_api_and_range(
        api.clone(),
        HttpsPortRange { start: 21_000, end: 21_002 },
    );
    let mut endpoint = spec(None);
    endpoint.public_port = Some(21_000);
    let (events, _receiver) = mpsc::channel(16);
    let error = driver
        .run(
            endpoint,
            crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
            events,
            CancellationToken::new(),
        )
        .await
        .expect_err("explicit conflict must fail");
    assert!(matches!(error, crate::DriverError::Capability(_)));
    assert_eq!(api.bindings.lock().len(), 1);
    assert_eq!(api.bindings.lock().get(&21_000).map(String::as_str), Some("http://127.0.0.1:9999"));
    assert!(!api.calls.lock().iter().any(|args| {
        args.iter().any(|arg| arg == "off") || args.iter().any(|arg| arg == "--https=21001")
    }));
}

#[tokio::test]
async fn automatic_retries_stay_in_configured_range() {
    let api = Arc::new(PortConflictApi::new([
        (443, "http://127.0.0.1:9999"),
        (21_000, "http://127.0.0.1:9998"),
    ]));
    let driver = TailscaleDriver::with_api_and_range(
        api.clone(),
        HttpsPortRange { start: 21_000, end: 21_001 },
    );
    let (events_tx, mut events_rx) = mpsc::channel(16);
    let stop = CancellationToken::new();
    let run_stop = stop.clone();
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let task =
        tokio::spawn(async move { driver.run(spec(None), target, events_tx, run_stop).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !matches!(events_rx.recv().await, Some(DriverEvent::Ready { .. })) {}
    })
    .await
    .expect("ready timeout");
    let attempted = api
        .calls
        .lock()
        .iter()
        .flat_map(|args| args.iter())
        .filter_map(|arg| arg.strip_prefix("--https="))
        .map(|port| port.parse::<u16>().expect("HTTPS port"))
        .collect::<Vec<_>>();
    assert_eq!(attempted, [21_001]);
    assert!(attempted.iter().all(|port| (21_000..=21_001).contains(port)));
    stop.cancel();
    task.await.expect("driver task").expect("clean shutdown");
}

#[tokio::test]
async fn persistent_entry_survives_manager_shutdown() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = TailscaleDriver::with_api(api.clone());
    let mut endpoint = spec(None);
    endpoint.persist = Persistence::Persistent;
    let (events_tx, mut events_rx) = mpsc::channel(16);
    let stop = CancellationToken::new();
    let (_forget_tx, forget) = tokio::sync::watch::channel(false);
    let (preserve_tx, preserve) = tokio::sync::watch::channel(false);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let run_stop = stop.clone();
    let task = tokio::spawn(async move {
        driver.run_controlled(endpoint, target, events_tx, run_stop, forget, preserve).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events_rx.recv().await {
                Some(DriverEvent::Ready { .. }) => break,
                Some(_) => {}
                None => panic!("driver closed before ready"),
            }
        }
    })
    .await
    .expect("ready timeout");
    preserve_tx.send(true).expect("preserve receiver");
    stop.cancel();
    task.await.expect("driver task").expect("clean shutdown");
    assert_eq!(api.installed.lock().as_deref(), Some("http://127.0.0.1:3000"));
    assert!(!api.calls.lock().iter().any(|args| args.last().is_some_and(|arg| arg == "off")));
}

#[test]
fn concurrent_public_binding_claims_are_rejected() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let directory = tempfile::tempdir().expect("ownership directory");
    let driver =
        TailscaleDriver::with_api_and_ownership(api.clone(), Some(directory.path().to_owned()));
    let other_process =
        TailscaleDriver::with_api_and_ownership(api, Some(directory.path().to_owned()));
    let endpoint = spec(None);
    let first_target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let second_target = crate::ResolvedTarget("127.0.0.1:4000".parse().expect("target"));
    let first = driver.claim_binding(&endpoint, first_target).expect("first claim");
    assert!(driver.claim_binding(&endpoint, second_target).is_err());
    assert!(other_process.claim_binding(&endpoint, second_target).is_err());
    let mut tcp = endpoint.clone();
    tcp.proto = ServiceProto::Tcp;
    tcp.public_port = Some(443);
    assert!(driver.claim_binding(&tcp, second_target).is_err());
    drop(first);
    assert!(other_process.claim_binding(&endpoint, second_target).is_ok());
}

#[tokio::test]
async fn already_absent_binding_is_safe_to_forget() {
    let api: Arc<dyn TailscaleApi> =
        Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let endpoint = spec(None);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let installed = CommandResult {
        success: true,
        stdout: r#"{"target":"http://127.0.0.1:3000"}"#.to_owned(),
        stderr: String::new(),
    };
    assert!(
        crate::drivers::tailscale_state::cleanup_if_unchanged(
            &api, "serve", &endpoint, target, &installed,
        )
        .await
        .expect("absent cleanup")
    );
}

#[test]
fn binding_ownership_marker_round_trips() {
    let directory = tempfile::tempdir().expect("ownership directory");
    let endpoint = spec(None);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    crate::drivers::tailscale_state::record_ownership(directory.path(), "serve", &endpoint, target)
        .expect("record ownership");
    assert!(crate::drivers::tailscale_state::owns_binding(
        directory.path(),
        "serve",
        &endpoint,
        target,
    ));
    crate::drivers::tailscale_state::forget_ownership(directory.path(), "serve", &endpoint, target)
        .expect("forget ownership");
    assert!(!crate::drivers::tailscale_state::owns_binding(
        directory.path(),
        "serve",
        &endpoint,
        target,
    ));
}

#[test]
fn status_comparison_ignores_unrelated_public_bindings() {
    let endpoint = spec(None);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let first = r#"{"TCP":{"443":{"HTTPS":true},"8443":{"TCPForward":"127.0.0.1:1"}},"Web":{"node:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"},"/other":{"Proxy":"http://127.0.0.1:1"}}},"node:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:1"}}}}}"#;
    let second = r#"{"TCP":{"443":{"HTTPS":true},"8443":{"TCPForward":"127.0.0.1:2"}},"Web":{"node:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"},"/other":{"Proxy":"http://127.0.0.1:2"}}},"node:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:2"}}}}}"#;
    assert_eq!(
        crate::drivers::tailscale_state::binding_snapshot(first, &endpoint, target),
        crate::drivers::tailscale_state::binding_snapshot(second, &endpoint, target)
    );
}

#[test]
fn serve_http_supports_stable_external_port() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = TailscaleDriver::with_api(api);
    let target = crate::ResolvedTarget("127.0.0.1:5173".parse().expect("target"));
    let mut endpoint = spec(None);
    endpoint.public_port = Some(28_461);

    driver.validate(&endpoint).expect("Serve HTTPS port");
    assert_eq!(
        install_args("serve", &endpoint, target, true),
        ["serve", "--bg", "--https=28461", "http://127.0.0.1:5173"]
    );
    let restarted_target = crate::ResolvedTarget("127.0.0.1:4012".parse().expect("target"));
    assert_eq!(
        install_args("serve", &endpoint, restarted_target, true),
        ["serve", "--bg", "--https=28461", "http://127.0.0.1:4012"]
    );
    assert_eq!(
        public_url(ServiceProto::Http, "node.example.ts.net", 28_461),
        "https://node.example.ts.net:28461"
    );
}

#[test]
fn funnel_http_supports_documented_public_ports() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = TailscaleDriver::with_api(api);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    for port in [443, 8443, 10000] {
        let mut endpoint = spec(Some("funnel"));
        endpoint.public_port = Some(port);
        driver.validate(&endpoint).expect("supported Funnel port");
        assert_eq!(
            install_args("funnel", &endpoint, target, true),
            vec![
                "funnel".to_owned(),
                "--bg".to_owned(),
                format!("--https={port}"),
                "http://127.0.0.1:3000".to_owned(),
            ]
        );
        let expected = if port == 443 {
            "https://node.example.ts.net".to_owned()
        } else {
            format!("https://node.example.ts.net:{port}")
        };
        assert_eq!(public_url(ServiceProto::Http, "node.example.ts.net", port), expected);
    }
}

#[test]
fn funnel_http_claims_configured_public_port() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = TailscaleDriver::with_api(api);
    let target = crate::ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let mut first = spec(Some("funnel"));
    first.public_port = Some(8443);
    let mut second = spec(Some("funnel"));
    second.public_port = Some(10000);
    let first_claim = driver.claim_binding(&first, target).expect("8443 claim");
    assert!(driver.claim_binding(&first, target).is_err());
    assert!(driver.claim_binding(&second, target).is_ok());
    drop(first_claim);
}

#[test]
fn funnel_rejects_unsupported_public_port() {
    let api = Arc::new(FakeApi { calls: Mutex::new(Vec::new()), installed: Mutex::new(None) });
    let driver = TailscaleDriver::with_api(api);
    let mut endpoint = spec(Some("funnel"));
    endpoint.proto = ServiceProto::Tcp;
    endpoint.public_port = Some(444);
    assert!(driver.validate(&endpoint).is_err());
}

#[test]
fn tcp_mapping_uses_requested_public_port() {
    let mut endpoint = spec(None);
    endpoint.proto = ServiceProto::Tcp;
    endpoint.public_port = Some(8443);
    let args = install_args(
        "serve",
        &endpoint,
        crate::ResolvedTarget("127.0.0.1:5432".parse().expect("target")),
        true,
    );
    assert_eq!(args, ["serve", "--bg", "--tcp=8443", "tcp://127.0.0.1:5432"]);
}

#[tokio::test]
#[ignore = "requires tailscale"]
async fn real_tailscale_health() {
    assert!(matches!(
        TailscaleDriver::system(crate::config::HttpsPortRange::default()).check().await,
        DriverHealth::Healthy
    ));
}
