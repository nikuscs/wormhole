use std::fs;

use wormhole_proto::frames::Persistence;

use super::{ProjectConfig, project_id};

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
  retry = { attempts = 5, backoff = "500ms" }
"#,
    )
    .expect("project");
    let project = ProjectConfig::load(directory.path()).expect("load");

    let selected = project.selected(&[], directory.path()).expect("selected");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1[0].persist, Persistence::Persistent);
    assert_eq!(selected[0].1[0].buffer.as_ref().expect("buffer").max_body_bytes, 1_048_576);
    assert_eq!(selected[0].1[0].retry.as_ref().expect("retry").initial_delay_ms, 500);
    assert_eq!(project_id(directory.path()).expect("id").len(), 64);
}
