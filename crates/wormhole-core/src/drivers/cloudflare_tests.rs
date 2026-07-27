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
        r"#!/usr/bin/env python3
import http.server,json,re,sys
with open(sys.argv[0]+'.log','a') as log: log.write(' '.join(sys.argv[1:])+'\n')
if '--version' in sys.argv:
 print('cloudflared version fake')
 sys.exit(0)
if 'create' in sys.argv:
 print('Created tunnel 018f47b4-0daf-7f89-8c42-177f615251bb')
 sys.exit(0)
if 'route' in sys.argv or 'list' in sys.argv:
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
",
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
    assert!(config.contains("http_status:404"));
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
}

#[tokio::test]
#[ignore = "requires cloudflared"]
async fn real_cloudflared_health() {
    assert_eq!(CloudflareDriver::system().check().await, DriverHealth::Healthy);
}
