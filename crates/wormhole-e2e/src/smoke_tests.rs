use std::process::Command;

use super::harness::{EchoServer, TestClient, TestRelay, binaries};

#[test]
#[ignore = "e2e"]
fn binary_harness_builds_and_discovers_both_programs() {
    let binaries = binaries().expect("binaries");
    for binary in [&binaries.wormhole, &binaries.wormholed] {
        let output = Command::new(binary).arg("--help").output().expect("binary help");
        assert!(output.status.success());
    }
}

#[test]
#[ignore = "e2e"]
fn relay_client_and_echo_server_round_trip() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let echo = EchoServer::start().expect("echo");
    let exposed = client
        .command(&[
            "--json",
            "http",
            &echo.port().to_string(),
            "--remote",
            "test",
            "--host",
            "smoke",
        ])
        .expect("expose");
    assert!(
        exposed.status.success(),
        "expose failed: {}\ndaemon log:\n{}",
        String::from_utf8_lossy(&exposed.stderr),
        client.daemon_log()
    );
    let endpoints: Vec<wormhole_core::ActiveEndpoint> =
        serde_json::from_slice(&exposed.stdout).expect("endpoint JSON");
    let url = format!("{}/hello", endpoints[0].urls[0].trim_end_matches('/'));
    let response = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--cacert",
            relay.certificate.to_str().expect("certificate path"),
            "--resolve",
            &format!("smoke.wormhole.test:{}:127.0.0.1", relay.port),
            &url,
        ])
        .output()
        .expect("curl");
    assert!(
        response.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&response.stderr)
    );
    let echoed: serde_json::Value = serde_json::from_slice(&response.stdout).expect("echo JSON");
    assert_eq!(echoed["method"], "GET");
    assert_eq!(echoed["uri"], "/hello");
    assert!(relay.config().exists());
}
