use std::fs;

use wormhole_proto::frames::Persistence;

use super::{ProjectConfig, parse_bytes, project_id};

#[test]
fn full_project_file_parses_policies_and_exact_id() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(
        directory.path().join("wormhole.toml"),
        r#"
name = "app"
[[service]]
name = "web"
target = "3000"
proto = "http"
  [[service.endpoint]]
  driver = "mock"
  persist = true
  buffer = { max_requests = 20, max_body = "1MiB", ttl = "2h" }
  auth = { basic = "user:pass", bearer = "secret", links = true }
  inspect = true
  capture_assets = true
  capture_body_max = "2MiB"
  retry = { attempts = 5, backoff = "500ms", max_backoff = "10s", on = ["connect-error", "5xx"], max_body = "2MiB", total_deadline = "30s" }
"#,
    )
    .expect("project");
    let project = ProjectConfig::load(directory.path()).expect("load");

    let selected = project.selected(&[], directory.path(), false).expect("selected");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1[0].persist, Persistence::Persistent);
    assert_eq!(selected[0].1[0].buffer.as_ref().expect("buffer").max_body_bytes, 1_048_576);
    assert!(selected[0].1[0].inspect);
    assert!(selected[0].1[0].inspect_assets);
    assert_eq!(selected[0].1[0].capture_body_max, 2 * 1024 * 1024);
    let auth = selected[0].1[0].auth.as_ref().expect("auth");
    assert!(auth.basic.is_some() && auth.bearer.is_some() && auth.link_key.is_some());
    let retry = selected[0].1[0].retry.as_ref().expect("retry");
    assert_eq!(retry.initial_delay_ms, 500);
    assert_eq!(retry.max_delay_ms, 10_000);
    assert!(retry.retry_5xx);
    assert_eq!(retry.max_body_bytes, 2 * 1024 * 1024);
    assert_eq!(project_id(directory.path()).expect("id").len(), 64);
}

#[test]
fn selection_infers_wormhole_hosts_and_rejects_unknown_or_invalid_policies() {
    let directory = tempfile::tempdir().expect("tempdir");
    let project: ProjectConfig = toml::from_str(
        r#"
name = "sample-app"
[[service]]
name = "web"
target = "localhost:3000"
proto = "http"
  [[service.endpoint]]
  driver = "wormhole:edge"
  [[service.endpoint]]
  driver = "cloudflare:named"
  host = "preview.example.com"
  persist = true
[[service]]
name = "tcp"
target = "9000"
proto = "tcp"
  [[service.endpoint]]
  driver = "mock"
"#,
    )
    .expect("project");

    let selected =
        project.selected(&["web".to_owned()], directory.path(), true).expect("selected service");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1[0].qualifier.as_deref(), Some("edge"));
    assert_eq!(selected[0].1[0].host, None);
    assert_eq!(selected[0].1[1].host.as_deref(), Some("preview.example.com"));
    assert!(selected[0].1[0].inspect);
    assert!(project.selected(&["missing".to_owned()], directory.path(), false).is_err());
    assert!(
        project.selected(&["web".to_owned(), "web".to_owned()], directory.path(), false).is_err()
    );

    for invalid in [
        "auth = { basic = \"missing-colon\" }",
        "auth = { bearer = \"\" }",
        "buffer = { max_requests = 1, max_body = \"bogus\", ttl = \"1m\" }",
        "retry = { attempts = 2, backoff = \"never\" }",
    ] {
        let source = format!(
            "[[service]]\nname = \"bad\"\ntarget = \"3000\"\nproto = \"http\"\n  [[service.endpoint]]\n  driver = \"mock\"\n  {invalid}\n"
        );
        let invalid: ProjectConfig = toml::from_str(&source).expect("parse invalid policy");
        assert!(invalid.selected(&[], directory.path(), false).is_err());
    }
}

#[test]
fn byte_sizes_cover_binary_decimal_invalid_and_overflow_cases() {
    assert_eq!(parse_bytes("1").expect("bytes"), 1);
    assert_eq!(parse_bytes("2B").expect("bytes"), 2);
    assert_eq!(parse_bytes("3KiB").expect("kibibytes"), 3 * 1024);
    assert_eq!(parse_bytes("4MiB").expect("mebibytes"), 4 * 1024 * 1024);
    assert_eq!(parse_bytes("1GiB").expect("gibibytes"), 1024 * 1024 * 1024);
    assert_eq!(parse_bytes("5KB").expect("kilobytes"), 5_000);
    assert_eq!(parse_bytes("6MB").expect("megabytes"), 6_000_000);
    assert_eq!(parse_bytes("1GB").expect("gigabytes"), 1_000_000_000);
    assert!(parse_bytes("abc").is_err());
    assert!(parse_bytes("1TiB").is_err());
    assert!(parse_bytes("18446744073709551615GB").is_err());
}
