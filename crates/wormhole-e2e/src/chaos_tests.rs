use std::{
    thread,
    time::{Duration, Instant},
};

use crate::{
    harness::{EchoServer, TestClient, TestRelay},
    helpers::spawn_relay_request,
    semantics_server::SemanticsServer,
};

#[test]
#[ignore = "e2e"]
fn relay_sigkill_reconnects_persistent_endpoint_on_same_ports() {
    let client = TestClient::isolated().expect("client");
    let mut relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let echo = EchoServer::start().expect("echo");
    let endpoints =
        client.expose_http(echo.port(), &["--host", "chaos", "--persist"]).expect("expose");
    let url = format!("{}/chaos", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "chaos.wormhole.test", &url), 200);
    relay.kill().expect("kill relay");
    wait_reconnecting(&client, Duration::from_secs(15));
    let started = Instant::now();
    relay.restart_same_ports().expect("restart relay");
    wait_status(&relay, "chaos.wormhole.test", &url, 200, Duration::from_secs(15));
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[test]
#[ignore = "e2e"]
fn daemon_sigkill_during_request_returns_without_hanging() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let server = SemanticsServer::start().expect("server");
    let endpoints = client.expose_http(server.port(), &["--host", "inflight"]).expect("expose");
    let url = format!("{}/slow", endpoints[0].urls[0].trim_end_matches('/'));
    let request =
        spawn_relay_request(&relay, "inflight.wormhole.test", &url, &["--max-time", "15"])
            .expect("request");
    thread::sleep(Duration::from_millis(200));
    client.kill_daemon().expect("kill daemon");
    let output = request.wait_with_output().expect("request output");
    assert!(output.status.success(), "curl: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(status_from_output(&output.stdout), 502);
}

fn wait_reconnecting(client: &TestClient, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let output = client.command(&["--json", "ls"]).expect("list");
        if output.status.success() {
            let endpoints: Vec<serde_json::Value> =
                serde_json::from_slice(&output.stdout).expect("endpoints");
            if endpoints.iter().any(|endpoint| endpoint["status"].as_str() == Some("reconnecting"))
            {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("endpoint did not enter reconnecting state");
}

fn wait_status(relay: &TestRelay, host: &str, url: &str, expected: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if request_status(relay, host, url) == expected {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("edge did not return {expected}");
}

fn request_status(relay: &TestRelay, host: &str, url: &str) -> u16 {
    relay.request(host, url).ok().map_or(0, |output| status_from_output(&output.stdout))
}

fn status_from_output(output: &[u8]) -> u16 {
    String::from_utf8_lossy(output)
        .rsplit_once('\n')
        .and_then(|(_, status)| status.parse().ok())
        .unwrap_or(0)
}
