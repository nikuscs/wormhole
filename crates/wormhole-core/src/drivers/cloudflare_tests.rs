use std::{fs, os::unix::fs::PermissionsExt as _, sync::Arc};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverEvent, DriverHealth, TunnelDriver},
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

use super::{CloudflareDriver, deterministic_name, named_config};

fn spec(mode: Option<&str>, persistence: Persistence) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "cloudflare".to_owned(),
        qualifier: mode.map(str::to_owned),
        remote: None,
        host: None,
        auto_host: false,
        domain: None,
        public_port: None,
        persist: persistence,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 1024 * 1024,
        reservation: None,
    }
}

fn fake_cloudflared(directory: &tempfile::TempDir) -> std::path::PathBuf {
    fake_cloudflared_named(directory, "cloudflared")
}

fn fake_cloudflared_named(directory: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let path = directory.path().join(name);
    fs::write(
        &path,
        r#"#!/usr/bin/env python3
import http.server,json,re,sys
with open(sys.argv[0]+'.log','a') as log: log.write(' '.join(sys.argv[1:])+'\n')
if '--version' in sys.argv:
 if 'versionfail' in sys.argv[0]:
  print('broken installation',file=sys.stderr); sys.exit(2)
 print('cloudflared version fake')
 sys.exit(0)
if 'create' in sys.argv:
 if 'tunnelfail' in sys.argv[0]:
  print('create denied',file=sys.stderr); sys.exit(2)
 if 'listfallback' not in sys.argv[0]:
  print('Created tunnel 018f47b4-0daf-7f89-8c42-177f615251bb')
 sys.exit(0)
if 'list' in sys.argv:
 if 'tunnelfail' in sys.argv[0]: sys.exit(2)
 print('[{"id":"018f47b4-0daf-7f89-8c42-177f615251bb"}]')
 sys.exit(0)
if 'route' in sys.argv:
 sys.exit(0)
if '--metrics' in sys.argv:
 metrics=sys.argv[sys.argv.index('--metrics')+1]
else:
 config=open(sys.argv[sys.argv.index('--config')+1]).read()
 metrics=re.search(r'metrics: ([^\n]+)',config).group(1)
port=int(metrics.rsplit(':',1)[1])
url='https://fixture.trycloudflare.com'
metric_url='https://other.trycloudflare.com' if 'mismatch' in sys.argv[0] else url
print(json.dumps({'event':'quickTunnel','url':url}),file=sys.stderr,flush=True)
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/quicktunnel' and 'logonly' in sys.argv[0]:
   self.send_response(404); self.end_headers(); return
  body=json.dumps({'hostname':metric_url}).encode() if self.path=='/quicktunnel' else b'ready'
  self.send_response(200); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
http.server.HTTPServer(('127.0.0.1',port),Handler).serve_forever()
"#,
    )
    .expect("script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
    path
}

#[tokio::test]
async fn quick_mode_discovers_matching_metric_and_log_url() {
    let directory = tempfile::tempdir().expect("tempdir");
    let driver = Arc::new(CloudflareDriver::with_binary(fake_cloudflared(&directory)));
    assert_eq!(driver.check().await, DriverHealth::Healthy);
    let (events, mut receiver) = mpsc::channel(32);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let driver = Arc::clone(&driver);
        let stop = stop.clone();
        async move {
            driver
                .run(
                    spec(None, Persistence::Temporary),
                    ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
                    events,
                    stop,
                )
                .await
        }
    });
    let mut ready = None;
    while let Some(event) = receiver.recv().await {
        if let DriverEvent::Ready { urls, .. } = event {
            ready = urls.first().cloned();
            break;
        }
    }
    assert_eq!(ready.as_deref(), Some("https://fixture.trycloudflare.com"));
    stop.cancel();
    task.await.expect("join").expect("driver");
}

#[tokio::test]
async fn quick_mode_falls_back_to_structured_log_url() {
    let directory = tempfile::tempdir().expect("tempdir");
    let driver: Arc<dyn TunnelDriver> = Arc::new(CloudflareDriver::with_binary(
        fake_cloudflared_named(&directory, "cloudflared-logonly"),
    ));
    crate::drivers::conformance::assert_lifecycle(
        driver,
        spec(None, Persistence::Temporary),
        || async { true },
    )
    .await;
}

#[test]
fn named_tunnels_are_distinct_and_have_catch_all_configs() {
    let first = deterministic_name("one.example.com");
    let second = deterministic_name("two.example.com");
    assert_ne!(first, second);
    assert_ne!(deterministic_name("a.b.example.com"), deterministic_name("a-b.example.com"));
    let home = tempfile::tempdir().expect("home");
    let config = named_config(
        home.path(),
        "018f47b4-0daf-7f89-8c42-177f615251bb",
        "one.example.com",
        ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
        20_001,
    );
    assert!(config.contains("hostname: one.example.com"));
    assert!(config.contains("service: http://127.0.0.1:3000"));
    assert!(config.contains("http_status:404"));
    let restarted = named_config(
        home.path(),
        "018f47b4-0daf-7f89-8c42-177f615251bb",
        "one.example.com",
        ResolvedTarget("127.0.0.1:4012".parse().expect("target")),
        20_002,
    );
    assert!(restarted.contains("hostname: one.example.com"));
    assert!(restarted.contains("service: http://127.0.0.1:4012"));
    assert_eq!(deterministic_name("one.example.com"), first);
}

#[tokio::test]
async fn named_mode_creates_distinct_tunnel_and_dns_commands() {
    let directory = tempfile::tempdir().expect("tempdir");
    let binary = fake_cloudflared(&directory);
    let home = directory.path().join("cloudflare-home");
    fs::create_dir(&home).expect("home");
    fs::write(home.join("cert.pem"), "fixture").expect("cert");
    let driver: Arc<dyn TunnelDriver> =
        Arc::new(CloudflareDriver::with_binary_and_home(binary.clone(), home));
    for host in ["one.example.com", "two.example.com"] {
        let mut endpoint = spec(Some("named"), Persistence::Persistent);
        endpoint.host = Some(host.to_owned());
        crate::drivers::conformance::assert_lifecycle(Arc::clone(&driver), endpoint, || async {
            true
        })
        .await;
    }
    let log = fs::read_to_string(format!("{}.log", binary.display())).expect("command log");
    let first = deterministic_name("one.example.com");
    let second = deterministic_name("two.example.com");
    assert!(log.contains(&format!("tunnel create {first}")));
    assert!(log.contains(&format!("tunnel create {second}")));
    assert_eq!(log.matches(&format!("route dns {first} one.example.com")).count(), 1);
    assert_eq!(log.matches(&format!("route dns {second} two.example.com")).count(), 1);
}

#[test]
fn concurrent_same_host_targets_cannot_share_a_tunnel() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("cloudflare-home");
    fs::create_dir(&home).expect("home");
    let binary = fake_cloudflared(&directory);
    let driver = CloudflareDriver::with_binary_and_home(binary.clone(), home.clone());
    let other_process = CloudflareDriver::with_binary_and_home(binary, home);
    let first = driver.claim_host("same.example.com").expect("first claim");
    assert!(driver.claim_host("same.example.com").is_err());
    assert!(other_process.claim_host("same.example.com").is_err());
    drop(first);
    assert!(other_process.claim_host("same.example.com").is_ok());
}

#[test]
fn named_route_ownership_is_scoped_to_host() {
    let home = tempfile::tempdir().expect("home");
    let target = ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let name = deterministic_name("one.example.com");
    crate::drivers::cloudflare_named::record_route(
        home.path(),
        &name,
        "018f47b4-0daf-7f89-8c42-177f615251bb",
        "one.example.com",
        target,
    )
    .expect("route marker");
    assert!(crate::drivers::cloudflare_named::route_is_owned(
        home.path(),
        &name,
        "one.example.com",
    ));
    assert!(!crate::drivers::cloudflare_named::route_is_owned(
        home.path(),
        &name,
        "other.example.com",
    ));
    crate::drivers::cloudflare_named::forget_route(home.path(), &name, "other.example.com")
        .expect("ignore unowned host");
    assert!(crate::drivers::cloudflare_named::route_is_owned(
        home.path(),
        &name,
        "one.example.com",
    ));
    crate::drivers::cloudflare_named::forget_route(home.path(), &name, "one.example.com")
        .expect("forget owned host");
    assert!(!crate::drivers::cloudflare_named::route_is_owned(
        home.path(),
        &name,
        "one.example.com",
    ));
}

#[test]
fn named_and_tcp_validation_is_strict() {
    let directory = tempfile::tempdir().expect("tempdir");
    let driver = CloudflareDriver::with_binary(fake_cloudflared(&directory));
    let named = spec(Some("named"), Persistence::Temporary);
    assert!(driver.validate(&named).is_err());
    let mut tcp = spec(None, Persistence::Temporary);
    tcp.proto = ServiceProto::Tcp;
    assert!(driver.validate(&tcp).is_err());

    let mut quick_persistent = spec(Some("quick"), Persistence::Persistent);
    assert!(driver.validate(&quick_persistent).is_err());
    quick_persistent.qualifier = Some("unsupported".to_owned());
    quick_persistent.persist = Persistence::Temporary;
    assert!(driver.validate(&quick_persistent).is_err());
    quick_persistent.qualifier = None;
    quick_persistent.domain = Some("example.com".to_owned());
    assert!(driver.validate(&quick_persistent).is_err());
}

#[tokio::test]
async fn degraded_binary_health_blocks_lifecycle_before_mutation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let driver = CloudflareDriver::with_binary(fake_cloudflared_named(
        &directory,
        "cloudflared-versionfail",
    ));
    assert!(
        matches!(driver.check().await, DriverHealth::Degraded(message) if message.contains("broken installation"))
    );
    let (events, mut receiver) = mpsc::channel(4);
    let error = driver
        .run(
            spec(None, Persistence::Temporary),
            ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
            events,
            CancellationToken::new(),
        )
        .await
        .expect_err("degraded preflight");
    assert!(error.to_string().contains("broken installation"));
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn named_diagnostics_and_tunnel_lookup_surface_actionable_failures() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("cloudflare-home");
    fs::create_dir(&home).expect("home");
    let fallback = CloudflareDriver::with_binary_and_home(
        fake_cloudflared_named(&directory, "cloudflared-listfallback"),
        home.clone(),
    );
    let diagnostics = fallback.diagnostics().await;
    assert!(matches!(
        diagnostics.as_slice(),
        [(base, DriverHealth::Healthy), (named, DriverHealth::Degraded(_))]
            if base == "cloudflare" && named == "cloudflare:named"
    ));
    assert_eq!(
        fallback.ensure_tunnel("fixture").await.expect("listed tunnel"),
        "018f47b4-0daf-7f89-8c42-177f615251bb"
    );

    let failing = CloudflareDriver::with_binary_and_home(
        fake_cloudflared_named(&directory, "cloudflared-tunnelfail"),
        home,
    );
    let error = failing.ensure_tunnel("fixture").await.expect_err("create and list fail");
    assert!(error.to_string().contains("create denied"));
}

#[tokio::test]
async fn unavailable_command_and_missing_home_diagnostics_are_actionable() {
    let unavailable = CloudflareDriver {
        binary: None,
        home: None,
        named_lock: tokio::sync::Mutex::new(()),
        active_hosts: super::HostClaims::default(),
    };
    assert!(matches!(
        unavailable.check().await,
        DriverHealth::Unavailable(message) if message.contains("brew install")
    ));
    assert!(unavailable.command(&["--version".to_owned()]).await.is_err());
    assert!(unavailable.ensure_tunnel("missing").await.is_err());
    assert!(unavailable.claim_host("missing.example.com").is_err());

    let directory = tempfile::tempdir().expect("tempdir");
    let command_failure = CloudflareDriver::with_binary(directory.path().to_owned());
    assert!(matches!(command_failure.check().await, DriverHealth::Degraded(_)));
    let healthy_without_home = CloudflareDriver {
        binary: Some(fake_cloudflared(&directory)),
        home: None,
        named_lock: tokio::sync::Mutex::new(()),
        active_hosts: super::HostClaims::default(),
    };
    let diagnostics = healthy_without_home.diagnostics().await;
    assert_eq!(healthy_without_home.capabilities(), crate::driver::DriverCapabilities::default());
    let mut named = spec(Some("named"), Persistence::Persistent);
    named.host = Some("missing.example.com".to_owned());
    let (events, _received) = mpsc::channel(1);
    assert!(
        healthy_without_home
            .prepare_named(
                &named,
                ResolvedTarget("127.0.0.1:3000".parse().expect("target")),
                &events,
            )
            .await
            .is_err()
    );
    assert!(matches!(
        diagnostics.as_slice(),
        [(base, DriverHealth::Healthy), (named, DriverHealth::Degraded(reason))]
            if base == "cloudflare"
                && named == "cloudflare:named"
                && reason.contains("config directory")
    ));
}

#[tokio::test]
async fn quick_start_failure_backs_off_then_honors_event_driven_cancellation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let driver = CloudflareDriver::with_binary(directory.path().join("missing-cloudflared"));
    let (events, mut received) = mpsc::channel(8);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move {
            driver
                .run_quick(ResolvedTarget("127.0.0.1:3000".parse().expect("target")), events, stop)
                .await
        }
    });

    assert!(matches!(received.recv().await, Some(DriverEvent::Log(_, _))));
    assert!(matches!(
        received.recv().await,
        Some(DriverEvent::StatusChanged(crate::model::EndpointStatus::Reconnecting))
    ));
    assert!(matches!(received.recv().await, Some(DriverEvent::Log(_, _))));
    stop.cancel();
    assert!(matches!(
        received.recv().await,
        Some(DriverEvent::StatusChanged(crate::model::EndpointStatus::Reconnecting))
    ));
    task.await.expect("retry task").expect("cancelled retry loop");
    assert!(matches!(received.recv().await, Some(DriverEvent::Closed)));
}

#[tokio::test]
#[ignore = "requires cloudflared"]
async fn real_cloudflared_health() {
    assert_eq!(CloudflareDriver::system().check().await, DriverHealth::Healthy);
}
