use std::{process::Command, time::Duration};

use crate::{
    harness::{EchoServer, TestClient, TestRelay},
    helpers::path,
    upload_server::UploadServer,
};

#[test]
#[ignore = "e2e"]
fn load_smoke_streaming_upload_and_fd_stability() {
    let client = TestClient::isolated().expect("client");
    let relay = TestRelay::start(&client.public_key()).expect("relay");
    client.configure(&relay).expect("client config");
    let echo = EchoServer::start().expect("echo");
    let endpoints = client.expose_http(echo.port(), &["--host", "load"]).expect("expose");
    let url = format!("{}/load", endpoints[0].urls[0].trim_end_matches('/'));
    let pid = daemon_pid(&client);
    let before = fd_count(pid);
    run_http_load(&client, &relay, &url);
    std::thread::sleep(Duration::from_millis(200));
    let after = fd_count(pid);
    if before > 0 && after > 0 {
        assert!(after <= before + 5, "fd count grew from {before} to {after}");
    }

    let upload = UploadServer::start().expect("upload server");
    let endpoints = client
        .expose_http(upload.port(), &["--host", "upload", "--no-inspect"])
        .expect("upload expose");
    let upload_url = format!("{}/upload", endpoints[0].urls[0].trim_end_matches('/'));
    let upload_result = stream_upload(&relay, &upload_url);
    assert!(
        upload_result.is_ok(),
        "{}; target received {}\n{}",
        upload_result.expect_err("failed upload"),
        upload.uploaded(),
        client.daemon_log()
    );
    assert_eq!(upload.uploaded(), 100 * 1024 * 1024,);
}

fn run_http_load(test_client: &TestClient, relay: &TestRelay, url: &str) {
    let certificate = std::fs::read(&relay.certificate).expect("certificate");
    let certificate = reqwest::Certificate::from_pem(&certificate).expect("PEM certificate");
    let client = reqwest::Client::builder()
        .add_root_certificate(certificate)
        .resolve(
            "load.wormhole.test",
            format!("127.0.0.1:{}", relay.port).parse().expect("relay address"),
        )
        .build()
        .expect("HTTP client");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        for index in 0..1000 {
            let response = client.get(url).send().await.expect("sequential request");
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                panic!("request {index}: {status}: {body}\n{}", test_client.daemon_log());
            }
        }
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let client = client.clone();
            let url = url.to_owned();
            requests.spawn(async move {
                let response = client.get(url).send().await?;
                let status = response.status();
                let body = response.text().await?;
                Ok::<_, reqwest::Error>((status, body))
            });
        }
        let mut failures = Vec::new();
        while let Some(response) = requests.join_next().await {
            let (status, body) = response.expect("request task").expect("concurrent request");
            if !status.is_success() {
                failures.push(format!("{status}: {body}"));
            }
        }
        assert!(
            failures.is_empty(),
            "concurrent failures: {failures:?}\n{}",
            test_client.daemon_log()
        );
    });
}

fn stream_upload(relay: &TestRelay, url: &str) -> Result<(), String> {
    let file = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
    file.as_file().set_len(100 * 1024 * 1024).map_err(|error| error.to_string())?;
    let upload = format!("@{}", path(file.path())?);
    let resolve = format!("upload.wormhole.test:{}:127.0.0.1", relay.port);
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            "60",
            "--cacert",
            path(&relay.certificate)?,
            "--resolve",
            &resolve,
            "--header",
            "Expect:",
            "--data-binary",
            &upload,
            url,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("curl upload: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

fn daemon_pid(client: &TestClient) -> u32 {
    let output = client.command(&["--json", "status"]).expect("daemon status");
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    status["pid"].as_u64().expect("daemon pid") as u32
}

fn fd_count(pid: u32) -> usize {
    let proc_path = format!("/proc/{pid}/fd");
    if let Ok(entries) = std::fs::read_dir(proc_path) {
        return entries.count();
    }
    let output = Command::new("lsof").args(["-a", "-p", &pid.to_string(), "-Fn"]).output();
    output.map_or(0, |output| {
        String::from_utf8_lossy(&output.stdout).lines().filter(|line| line.starts_with('f')).count()
    })
}
