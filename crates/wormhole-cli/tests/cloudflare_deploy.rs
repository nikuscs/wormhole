use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    process::Command,
    sync::{Arc, Mutex},
};

use axum::{Router, body::Body, extract::State, http::Request, response::Response, routing::any};

#[test]
fn dry_run_uses_local_bundle_without_cloudflare_credentials() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bundle = fixture_bundle(&directory);
    let log = directory.path().join("wrangler.log");
    let wrangler = mock_wrangler(&directory, &log, None, false, false, false);

    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .args(["--dry-run", "--json"])
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .expect("wormhole");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let view: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(view["status"], "dry_run");
    assert_eq!(view["domain"], "example.com");
    assert_eq!(view["relay_domain"], "relay.example.com");
    let arguments = fs::read_to_string(log).expect("Wrangler arguments");
    assert!(arguments.contains("deploy"));
    assert!(arguments.contains("--dry-run"));
    assert!(arguments.contains("RELAY_DOMAIN:example.com"));
    assert!(arguments.contains("CONTROL_DOMAIN:relay.example.com"));
    assert!(arguments.contains("relay.example.com/*"));
    assert!(arguments.contains("*.example.com/*"));
    assert!(!arguments.to_ascii_lowercase().contains("token"));

    let human = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .arg("--dry-run")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .output()
        .expect("wormhole human output");
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Cloudflare deployment validated"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_deploy_keeps_credentials_out_of_arguments_and_output() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bundle = fixture_bundle(&directory);
    let log = directory.path().join("wrangler.log");
    let secret_input = directory.path().join("secret-input.json");
    let wrangler = mock_wrangler(&directory, &log, Some(&secret_input), false, false, false);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().fallback(any(mock_cloudflare)).with_state(Arc::clone(&requests));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
    let config = directory.path().join("config.toml");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");

    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args([
            "relay",
            "deploy",
            "cloudflare",
            "--domain",
            "example.com",
            "--remote-name",
            "edge",
            "--bundle",
        ])
        .arg(&bundle)
        .args(["--yes", "--json", "--config"])
        .arg(&config)
        .env("HOME", &home)
        .env("CLOUDFLARE_API_TOKEN", "provider-test-token")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env("WORMHOLE_CLOUDFLARE_API_BASE", format!("http://{address}/client/v4"))
        .env("WORMHOLE_CLOUDFLARE_RELAY_BASE", format!("http://{address}"))
        .env("WORMHOLE_CLOUDFLARE_SKIP_ENROLL", "1")
        .output()
        .expect("wormhole");
    server.abort();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let view: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(view["status"], "deployed");
    assert_eq!(view["remote"], "edge");
    let all_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all_output.contains("provider-test-token"));
    assert!(!all_output.contains("invite-test-secret"));
    let arguments = fs::read_to_string(&log).expect("Wrangler log");
    assert!(!arguments.contains("provider-test-token"));
    assert!(arguments.contains("secret bulk"));
    let secrets: serde_json::Value =
        serde_json::from_slice(&fs::read(secret_input).expect("secret input"))
            .expect("secrets JSON");
    assert!(secrets["ADMIN_TOKEN"].as_str().is_some_and(|value| value.len() >= 32));
    assert!(secrets["EDGE_AUTH_KEY"].as_str().is_some_and(|value| value.len() >= 32));
    assert!(fs::read_to_string(config).expect("config").contains("transport = \"ws\""));
    let token_file = find_file(&home, ".admin-token").expect("saved administrator token");
    assert_eq!(fs::metadata(token_file).expect("metadata").mode() & 0o077, 0);
    let calls = requests.lock().expect("requests");
    assert!(calls.iter().any(|call| call == "GET /health"));
    assert!(
        calls.iter().any(|call| {
            call == "GET /client/v4/zones?name=example.com&status=active&per_page=5"
        })
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("POST /client/v4/zones/zone/dns_records"))
            .count(),
        2
    );
    assert!(calls.iter().any(|call| call == "DNS relay.example.com"));
    assert!(calls.iter().any(|call| call == "DNS *.example.com"));
    assert!(!calls.iter().any(|call| call == "DNS example.com"));
    drop(calls);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_dns_uses_wrangler_oauth_without_provider_token() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bundle = fixture_bundle(&directory);
    let log = directory.path().join("wrangler.log");
    let secret_input = directory.path().join("secret-input.json");
    let wrangler = mock_wrangler(&directory, &log, Some(&secret_input), false, false, true);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().fallback(any(mock_cloudflare)).with_state(Arc::clone(&requests));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
    let config = directory.path().join("config.toml");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");

    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .args(["--manual-dns", "--yes", "--json", "--config"])
        .arg(&config)
        .env("HOME", &home)
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env("WORMHOLE_CLOUDFLARE_API_BASE", "http://127.0.0.1:1/forbidden")
        .env("WORMHOLE_CLOUDFLARE_RELAY_BASE", format!("http://{address}"))
        .env("WORMHOLE_CLOUDFLARE_SKIP_ENROLL", "1")
        .output()
        .expect("wormhole");
    server.abort();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let view: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(view["status"], "deployed");
    assert!(view["dns_records_created"].as_array().is_some_and(Vec::is_empty));
    let arguments = fs::read_to_string(log).expect("Wrangler log");
    assert!(arguments.contains("whoami --json"));
    assert!(arguments.contains("secret bulk"));
    let calls = requests.lock().expect("requests");
    assert!(calls.iter().all(|call| !call.contains("/client/v4/")));
    assert!(calls.iter().any(|call| call == "GET /health"));
    drop(calls);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_secret_upload_rolls_back_worker_and_created_dns() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bundle = fixture_bundle(&directory);
    let log = directory.path().join("wrangler.log");
    let secret_input = directory.path().join("secret-input.json");
    let wrangler = mock_wrangler(&directory, &log, Some(&secret_input), true, false, false);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().fallback(any(mock_cloudflare)).with_state(Arc::clone(&requests));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });

    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .args(["--yes", "--json"])
        .env("CLOUDFLARE_API_TOKEN", "provider-test-token")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env("WORMHOLE_CLOUDFLARE_API_BASE", format!("http://{address}/client/v4"))
        .output()
        .expect("wormhole");
    server.abort();

    assert!(!output.status.success());
    let arguments = fs::read_to_string(log).expect("Wrangler log");
    assert!(arguments.contains("delete wormhole-example-a379a6f6 --force"));
    let calls = requests.lock().expect("requests");
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("DELETE /client/v4/zones/zone/dns_records/"))
            .count(),
        2
    );
    drop(calls);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_deploy_preserves_secrets() {
    let directory = tempfile::tempdir().expect("tempdir");
    let bundle = fixture_bundle(&directory);
    let log = directory.path().join("wrangler.log");
    let wrangler = mock_wrangler(&directory, &log, None, false, true, false);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().fallback(any(mock_cloudflare)).with_state(requests);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
    let config = directory.path().join("config.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .args(["--yes", "--json", "--config"])
        .arg(&config)
        .env("CLOUDFLARE_API_TOKEN", "provider-test-token")
        .env("WORMHOLE_CLOUDFLARE_ADMIN_TOKEN", "existing-admin-test-token")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env("WORMHOLE_CLOUDFLARE_API_BASE", format!("http://{address}/client/v4"))
        .env("WORMHOLE_CLOUDFLARE_RELAY_BASE", format!("http://{address}"))
        .env("WORMHOLE_CLOUDFLARE_SKIP_ENROLL", "1")
        .output()
        .expect("wormhole");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let all_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all_output.contains("existing-admin-test-token"));
    let arguments = fs::read_to_string(&log).expect("Wrangler log");
    assert!(!arguments.contains("secret bulk"));

    let noninteractive = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(["relay", "deploy", "cloudflare", "--domain", "example.com", "--bundle"])
        .arg(&bundle)
        .env("CLOUDFLARE_API_TOKEN", "provider-test-token")
        .env("WORMHOLE_CLOUDFLARE_ADMIN_TOKEN", "existing-admin-test-token")
        .env("WORMHOLE_CLOUDFLARE_WRANGLER", &wrangler)
        .env("WORMHOLE_CLOUDFLARE_API_BASE", format!("http://{address}/client/v4"))
        .output()
        .expect("noninteractive wormhole");
    server.abort();
    assert!(!noninteractive.status.success());
    assert!(String::from_utf8_lossy(&noninteractive.stderr).contains("requires `--yes`"));
}

fn fixture_bundle(directory: &tempfile::TempDir) -> std::path::PathBuf {
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(bundle.join("build")).expect("bundle");
    fs::write(
        bundle.join("manifest.json"),
        r#"{"schema":1,"wormhole_version":"0.0.0","wrangler_version":"4.115.0"}"#,
    )
    .expect("manifest");
    fs::write(bundle.join("wrangler.jsonc"), "{}").expect("config");
    fs::write(bundle.join("build/index.js"), "export default {};").expect("js");
    fs::write(bundle.join("build/index_bg.wasm"), b"wasm").expect("wasm");
    bundle
}

fn mock_wrangler(
    directory: &tempfile::TempDir,
    log: &std::path::Path,
    secret_input: Option<&std::path::Path>,
    fail_secret: bool,
    existing: bool,
    reject_token_env: bool,
) -> std::path::PathBuf {
    let wrangler = directory.path().join("wrangler-mock");
    let secret =
        secret_input.map_or_else(|| "/dev/null".to_owned(), |path| path.display().to_string());
    let secret_exit = if fail_secret { "echo 'secret failure' >&2; exit 1" } else { "exit 0" };
    let token_check = if reject_token_env {
        "if [ -n \"$CLOUDFLARE_API_TOKEN\" ]; then echo 'unexpected token env' >&2; exit 9; fi"
    } else {
        ":"
    };
    let status_exit = if existing {
        "exit 0"
    } else {
        "echo 'Worker does not exist' >&2; echo 'Logs were written to test.log' >&2; exit 1"
    };
    fs::write(
        &wrangler,
        format!(
            "#!/bin/sh\n{token_check}\nprintf '%s ' \"$@\" >> '{log}'\nprintf '\\n' >> '{log}'\ncase \"$*\" in\n  'deployments status'*) {status_exit};;\n  'secret bulk'*) cat > '{secret}'; {secret_exit};;\nesac\nexit 0\n",
            log = log.display()
        ),
    )
    .expect("mock");
    fs::set_permissions(&wrangler, fs::Permissions::from_mode(0o700)).expect("mode");
    wrangler
}

async fn mock_cloudflare(
    State(calls): State<Arc<Mutex<Vec<String>>>>,
    request: Request<Body>,
) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let path_and_query =
        request.uri().path_and_query().map_or_else(|| path.clone(), ToString::to_string);
    calls.lock().expect("calls").push(format!("{method} {path_and_query}"));
    let mut status = 200;
    let body = match (method.as_str(), path.as_str()) {
        ("GET", "/client/v4/zones") => {
            serde_json::json!({"success":true,"result":[{"id":"zone","name":"example.com"}]})
        }
        ("GET", "/client/v4/zones/zone/dns_records") => {
            serde_json::json!({"success":true,"result":[]})
        }
        ("POST", "/client/v4/zones/zone/dns_records") => {
            let bytes = axum::body::to_bytes(request.into_body(), 8192).await.expect("DNS body");
            let input: serde_json::Value = serde_json::from_slice(&bytes).expect("DNS JSON");
            calls
                .lock()
                .expect("calls")
                .push(format!("DNS {}", input["name"].as_str().expect("DNS name")));
            serde_json::json!({"success":true,"result":{"id":input["name"],"name":input["name"],"proxied":true}})
        }
        ("GET", "/health") => serde_json::json!({"ok":true}),
        ("POST", "/_wormhole/admin/invites") => {
            let attempts = calls
                .lock()
                .expect("calls")
                .iter()
                .filter(|call| call.as_str() == "POST /_wormhole/admin/invites")
                .count();
            if attempts == 1 {
                status = 522;
                serde_json::json!({"error":"route still propagating"})
            } else {
                serde_json::json!({"token":"invite-test-secret"})
            }
        }
        _ => serde_json::json!({"success":false,"errors":[{"message":"unexpected test request"}]}),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("response")
}

fn find_file(root: &std::path::Path, suffix: &str) -> Option<std::path::PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, suffix) {
                return Some(found);
            }
        } else if path.to_string_lossy().ends_with(suffix) {
            return Some(path);
        }
    }
    None
}
