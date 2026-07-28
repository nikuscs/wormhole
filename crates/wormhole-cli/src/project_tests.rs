use std::fs;

use wormhole_proto::frames::Persistence;

use super::{ProjectConfig, project_id};

fn documented_project_blocks() -> Vec<(String, String)> {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut blocks = Vec::new();
    for entry in fs::read_dir(docs).expect("read docs") {
        let path = entry.expect("docs entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("md") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read markdown");
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line != "```toml" {
                continue;
            }
            let block =
                lines.by_ref().take_while(|line| *line != "```").collect::<Vec<_>>().join("\n");
            if block.contains("[[service]]") {
                blocks.push((path.display().to_string(), block));
            }
        }
    }
    blocks
}

#[test]
fn documented_project_toml_blocks_parse() {
    let blocks = documented_project_blocks();
    assert!(!blocks.is_empty(), "project documentation must include TOML");
    for (path, block) in blocks {
        toml::from_str::<ProjectConfig>(&block)
            .unwrap_or_else(|error| panic!("invalid project TOML in {path}: {error}"));
    }
}

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
