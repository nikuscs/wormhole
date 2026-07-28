use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use tokio_tungstenite::{
    Connector, client_async_tls_with_config, tungstenite::client::IntoClientRequest as _,
};

use std::{
    io::{Read as _, Write as _},
    net::{Shutdown, TcpStream},
    thread,
    time::{Duration, Instant},
};

use super::{
    harness::{EchoServer, TcpEchoServer, TestClient, TestRelay},
    helpers::{relay_command, set_remote_port, set_transport, spawn_client},
    semantics_server::SemanticsServer,
};

#[test]
#[ignore = "e2e"]
fn temporary_http_bind_serves_then_disappears() {
    let (client, relay, echo) = fixture();
    let endpoints = client.expose_http(echo.port(), &["--host", "temporary"]).expect("expose");
    let url = format!("{}/matrix", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "temporary.wormhole.test", &url), 200);
    let down = client.command(&["down", &endpoints[0].id.to_string()]).expect("down");
    assert!(down.status.success(), "down: {}", String::from_utf8_lossy(&down.stderr));
    assert_eq!(request_status(&relay, "temporary.wormhole.test", &url), 404);
}

#[test]
#[ignore = "e2e"]
fn forced_websocket_transport_serves_http() {
    let (client, relay, echo) = fixture();
    set_remote_port(&client.config, relay.port).expect("WebSocket port");
    set_transport(&client.config, "ws").expect("WebSocket transport");
    let endpoints = client.expose_http(echo.port(), &["--host", "websocket"]).expect("expose");
    let url = format!("{}/ws", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "websocket.wormhole.test", &url), 200);
}

#[test]
#[ignore = "e2e"]
fn auto_transport_falls_back_when_udp_is_blocked() {
    let (client, relay, echo) = fixture();
    set_remote_port(&client.config, relay.port).expect("TCP-only remote");
    let endpoints = client
        .expose_http(echo.port(), &["--host", "fallback"])
        .unwrap_or_else(|error| panic!("{error}\n{}", client.daemon_log()));
    let url = format!("{}/fallback", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "fallback.wormhole.test", &url), 200);
}

#[test]
#[ignore = "e2e"]
fn forced_quic_transport_serves_http() {
    let (client, relay, echo) = fixture();
    set_transport(&client.config, "quic").expect("QUIC transport");
    let endpoints = client.expose_http(echo.port(), &["--host", "quic"]).expect("expose");
    let url = format!("{}/quic", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "quic.wormhole.test", &url), 200);
}

#[test]
#[ignore = "e2e"]
fn one_service_exposes_to_two_relays() {
    let client = TestClient::isolated().expect("client");
    let first = TestRelay::start(&client.public_key()).expect("first relay");
    let second = TestRelay::start(&client.public_key()).expect("second relay");
    client.configure_two(&first, &second).expect("client config");
    let echo = EchoServer::start().expect("echo");
    client
        .write_project(&format!(
            "name = \"multi-remote\"\n[[service]]\nname = \"web\"\ntarget = \"{}\"\nproto = \"http\"\n[[service.endpoint]]\ndriver = \"wormhole\"\nremote = \"first\"\nhost = \"first\"\n[[service.endpoint]]\ndriver = \"wormhole\"\nremote = \"second\"\nhost = \"second\"\n",
            echo.port()
        ))
        .expect("project");
    let up = client.command(&["--json", "up"]).expect("up");
    assert!(up.status.success(), "up: {}", String::from_utf8_lossy(&up.stderr));
    let endpoints: Vec<wormhole_core::ActiveEndpoint> =
        serde_json::from_slice(&up.stdout).expect("endpoints");
    assert_eq!(endpoints.len(), 2);
    let first_url = endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.urls)
        .find(|url| url.contains("first.wormhole.test"))
        .expect("first URL");
    let second_url = endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.urls)
        .find(|url| url.contains("second.wormhole.test"))
        .expect("second URL");
    assert_eq!(request_status(&first, "first.wormhole.test", first_url), 200);
    assert_eq!(request_status(&second, "second.wormhole.test", second_url), 200);
}

#[test]
#[ignore = "e2e"]
fn multi_endpoint_closes_independently() {
    let (client, relay, echo) = fixture();
    let output = client
        .command(&[
            "--json",
            "http",
            &echo.port().to_string(),
            "--endpoint",
            "wormhole",
            "--endpoint",
            "mock",
            "--host",
            "multi",
        ])
        .expect("expose");
    assert!(output.status.success(), "expose: {}", String::from_utf8_lossy(&output.stderr));
    let endpoints: Vec<wormhole_core::ActiveEndpoint> =
        serde_json::from_slice(&output.stdout).expect("endpoints");
    assert_eq!(endpoints.len(), 2);
    let mock = endpoints.iter().find(|endpoint| endpoint.driver == "mock").expect("mock");
    let wormhole =
        endpoints.iter().find(|endpoint| endpoint.driver == "wormhole").expect("wormhole");
    let down = client.command(&["down", &mock.id.to_string()]).expect("down mock");
    assert!(down.status.success());
    let url = format!("{}/still-live", wormhole.urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "multi.wormhole.test", &url), 200);
}

#[test]
#[ignore = "e2e"]
fn offline_webhook_buffers_and_replays_after_restore() {
    let (client, relay, echo) = fixture();
    let endpoints = client
        .expose_http(echo.port(), &["--host", "buffer", "--persist", "--buffer", "10"])
        .expect("expose");
    let url = format!("{}/webhook", endpoints[0].urls[0].trim_end_matches('/'));
    client.stop_daemon();
    let buffered = relay
        .request_with("buffer.wormhole.test", &url, &["--request", "POST", "--data", "event=one"])
        .expect("buffer request");
    assert_eq!(status_from_output(buffered), 202);
    let status = client.command(&["--json", "status"]).expect("restart daemon");
    assert!(status.status.success());
    let deadline = Instant::now() + Duration::from_secs(15);
    while echo.request_count() == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(echo.request_count(), 1);
    let listed = client.command(&["--json", "ls"]).expect("list");
    let restored: Vec<wormhole_core::ActiveEndpoint> =
        serde_json::from_slice(&listed.stdout).expect("endpoints");
    assert_eq!(restored[0].buffered_delivered, 1);
}

#[test]
#[ignore = "e2e"]
fn failed_webhook_can_be_retried_after_later_delivery() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let server = SemanticsServer::start().expect("flaky server");
    let endpoints = client
        .expose_http(server.port(), &["--host", "failed", "--persist", "--buffer", "10"])
        .expect("expose");
    let url = format!("{}/webhook", endpoints[0].urls[0].trim_end_matches('/'));
    client.stop_daemon();
    for body in ["one", "two"] {
        let response = relay
            .request_with("failed.wormhole.test", &url, &["--request", "POST", "--data", body])
            .expect("buffered request");
        assert_eq!(status_from_output(response), 202);
    }
    assert!(client.command(&["--json", "status"]).expect("restart").status.success());
    let deadline = Instant::now() + Duration::from_secs(15);
    while server.deliveries() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(server.deliveries(), 2);
    let listed =
        relay_command(&relay, &["webhooks", "failed", "ls", "--json"]).expect("failed list");
    assert!(listed.status.success(), "list: {}", String::from_utf8_lossy(&listed.stderr));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&listed.stdout).expect("failed rows");
    assert_eq!(rows.len(), 1);
    let bind = rows[0]["bind"].as_str().expect("bind");
    let seq = rows[0]["seq"].as_u64().expect("seq").to_string();
    let retried =
        relay_command(&relay, &["webhooks", "failed", "retry", bind, &seq]).expect("retry");
    assert!(retried.status.success(), "retry: {}", String::from_utf8_lossy(&retried.stderr));
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.deliveries() < 3 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(server.deliveries(), 3);
}

#[test]
#[ignore = "e2e"]
fn inspection_lists_and_replays_real_request() {
    let (client, relay, echo) = fixture();
    let endpoints = client.expose_http(echo.port(), &["--host", "inspect"]).expect("expose");
    let url = format!("{}/captured", endpoints[0].urls[0].trim_end_matches('/'));
    assert_eq!(request_status(&relay, "inspect.wormhole.test", &url), 200);
    let listed = client.command(&["--json", "requests"]).expect("requests");
    let captures: Vec<wormhole_core::CapturedRequest> =
        serde_json::from_slice(&listed.stdout).expect("captures");
    let capture = captures.iter().find(|capture| capture.uri == "/captured").expect("capture");
    let replay_output =
        client.command(&["--json", "replay", &capture.id.to_string()]).expect("replay");
    assert!(
        replay_output.status.success(),
        "replay: {}",
        String::from_utf8_lossy(&replay_output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&replay_output.stdout).expect("replay JSON");
    assert_eq!(result["status"], 200);
}

#[test]
#[ignore = "e2e"]
fn http_semantics_survive_typed_tunnel() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let server = SemanticsServer::start().expect("semantics server");
    let endpoints = client.expose_http(server.port(), &["--host", "semantics"]).expect("expose");
    let base = endpoints[0].urls[0].trim_end_matches('/');

    let cookies = relay
        .request_with(
            "semantics.wormhole.test",
            &format!("{base}/cookies"),
            &["--dump-header", "-"],
        )
        .expect("cookies");
    let cookies = String::from_utf8(cookies.stdout).expect("cookie response");
    assert_eq!(cookies.to_ascii_lowercase().matches("set-cookie:").count(), 2);
    assert!(cookies.contains("hello world"));

    let headers = relay
        .request_with(
            "semantics.wormhole.test",
            &format!("{base}/headers"),
            &["--header", "X-Client: preserved"],
        )
        .expect("headers");
    let headers = String::from_utf8(headers.stdout).expect("header response").to_ascii_lowercase();
    assert!(headers.contains("x-client: preserved"));
    assert!(headers.contains("x-forwarded-for:"));

    let cancelled = relay
        .request_with("semantics.wormhole.test", &format!("{base}/slow"), &["--max-time", "0.2"])
        .expect("cancelled request");
    assert!(!cancelled.status.success());
    assert_eq!(request_status(&relay, "semantics.wormhole.test", &format!("{base}/")), 200);
    websocket_roundtrip(&relay, &format!("{base}/upgrade"));
}

fn websocket_roundtrip(relay: &TestRelay, url: &str) {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&relay.certificate).expect("certificate") {
        roots.add(certificate.expect("PEM certificate")).expect("trusted certificate");
    }
    let tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let ws_url = url.replacen("https://", "wss://", 1);
        let request = ws_url.into_client_request().expect("WebSocket request");
        let stream =
            tokio::net::TcpStream::connect(("127.0.0.1", relay.port)).await.expect("public edge");
        let (socket, response) = client_async_tls_with_config(
            request,
            stream,
            None,
            Some(Connector::Rustls(std::sync::Arc::new(tls))),
        )
        .await
        .expect("WebSocket upgrade");
        assert_eq!(response.status().as_u16(), 101);
        drop(socket);
    });
}

#[test]
#[ignore = "e2e"]
fn edge_bearer_auth_rejects_then_accepts() {
    let (client, relay, echo) = fixture();
    let endpoints = client
        .expose_http(echo.port(), &["--host", "auth", "--auth", "bearer:secret"])
        .expect("expose");
    let url = endpoints[0].urls[0].clone();
    assert_eq!(request_status(&relay, "auth.wormhole.test", &url), 401);
    let authorized = relay
        .request_with("auth.wormhole.test", &url, &["--header", "Authorization: Bearer secret"])
        .expect("authorized request");
    assert_eq!(status_from_output(authorized), 200);
}

#[test]
#[ignore = "e2e"]
fn run_serves_child_and_cleans_up_after_exit() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let app_port = free_port();
    let app_port_text = app_port.to_string();
    let mut child = spawn_client(
        &client,
        &[
            "--json",
            "run",
            "--app-port",
            &app_port_text,
            "--remote",
            "test",
            "--host",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "python3 -m http.server \"$PORT\" --bind 127.0.0.1 >/dev/null 2>&1 & pid=$!; sleep 8; kill $pid; wait $pid || true",
        ],
    )
    .expect("run command");
    let url = format!("https://run.wormhole.test:{}/", relay.port);
    wait_for_status(&relay, "run.wormhole.test", &url, 200, Duration::from_secs(10));
    let deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break status;
        }
        assert!(Instant::now() < deadline, "run command did not exit");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "run command failed: {status}");
    wait_for_status(&relay, "run.wormhole.test", &url, 404, Duration::from_secs(5));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

#[test]
#[ignore = "e2e"]
fn unauthorized_and_revoked_keys_exit_four() {
    let unauthorized = TestClient::isolated().expect("unauthorized client");
    let other = wormhole_proto::Identity::generate();
    let relay = TestRelay::start(&other.public_base64()).expect("relay");
    unauthorized.configure(&relay).expect("client config");
    let echo = EchoServer::start().expect("echo");
    assert_denied(&unauthorized, echo.port(), "unknown");

    let authorized = TestClient::isolated().expect("authorized client");
    let relay = TestRelay::start(&authorized.public_key()).expect("relay");
    authorized.configure(&relay).expect("client config");
    relay.revoke(&authorized.fingerprint()).expect("revoke");
    assert_denied(&authorized, echo.port(), "revoked");
}

fn assert_denied(client: &TestClient, port: u16, host: &str) {
    let output = client
        .command(&[
            "--json",
            "http",
            &port.to_string(),
            "--remote",
            "test",
            "--host",
            host,
            "--foreground",
        ])
        .expect("foreground expose");
    assert_eq!(
        output.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).to_ascii_lowercase().contains("denied"));
}

#[test]
#[ignore = "e2e"]
fn tcp_forward_round_trips_bytes() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let echo = TcpEchoServer::start().expect("TCP echo");
    client.expose_tcp(echo.port(), 24_050).expect("expose TCP");
    let mut stream = TcpStream::connect(("127.0.0.1", 24_050)).expect("public TCP");
    stream.write_all(b"round-trip").expect("write");
    stream.shutdown(Shutdown::Write).expect("half-close");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read");
    assert_eq!(response, b"round-trip");
}

#[test]
#[ignore = "e2e"]
fn persistent_http_bind_restores_after_daemon_sigkill() {
    let (client, relay, echo) = fixture();
    let endpoints =
        client.expose_http(echo.port(), &["--host", "persistent", "--persist"]).expect("expose");
    let original_url = endpoints[0].urls[0].clone();
    let url = format!("{}/restore", original_url.trim_end_matches('/'));
    assert_eq!(request_status(&relay, "persistent.wormhole.test", &url), 200);
    client.kill_daemon().expect("kill daemon");
    wait_for_status(&relay, "persistent.wormhole.test", &url, 503, Duration::from_secs(15));
    let status = client.command(&["--json", "status"]).expect("auto-spawn status");
    assert!(status.status.success(), "status: {}", String::from_utf8_lossy(&status.stderr));
    wait_for_status(&relay, "persistent.wormhole.test", &url, 200, Duration::from_secs(15));
    let listed = client.command(&["--json", "ls"]).expect("list");
    let restored: Vec<wormhole_core::ActiveEndpoint> =
        serde_json::from_slice(&listed.stdout).expect("restored endpoints");
    assert!(restored.iter().any(|endpoint| endpoint.urls.contains(&original_url)));
}

fn fixture() -> (TestClient, TestRelay, EchoServer) {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let echo = EchoServer::start().expect("echo");
    (client, relay, echo)
}

fn request_status(relay: &TestRelay, host: &str, url: &str) -> u16 {
    status_from_output(relay.request(host, url).expect("request"))
}

fn status_from_output(output: std::process::Output) -> u16 {
    let text = String::from_utf8(output.stdout).expect("UTF-8 curl output");
    text.rsplit_once('\n')
        .and_then(|(_, status)| status.parse().ok())
        .unwrap_or_else(|| panic!("missing status in {text:?}"))
}

fn wait_for_status(relay: &TestRelay, host: &str, url: &str, expected: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last = 0;
    while Instant::now() < deadline {
        last = request_status(relay, host, url);
        if last == expected {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("status did not become {expected}; last={last}");
}
