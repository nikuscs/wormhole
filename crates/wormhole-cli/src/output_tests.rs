use serde::Serialize;

use super::{Format, HumanRender, emit};

#[derive(Serialize)]
struct DummyOutput {
    status: &'static str,
}

impl HumanRender for DummyOutput {
    fn render(&self) -> String {
        self.status.to_owned()
    }
}

#[test]
fn emits_both_output_formats() {
    let value = DummyOutput { status: "ok" };

    emit(Format::Human, &value);
    emit(Format::Json, &value);
}

#[test]
fn forced_tty_endpoint_output_is_stable() {
    let endpoints = vec![wormhole_core::ActiveEndpoint {
        id: "01900000-0000-7000-8000-000000000000".parse().expect("uuid"),
        service: "web".to_owned(),
        driver: "wormhole".to_owned(),
        urls: vec!["https://web.example.com".to_owned()],
        status: wormhole_core::model::EndpointStatus::Online,
        buffered_delivered: 0,
        buffered_pending: 0,
        buffered_failed: 0,
        since: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }];

    insta::assert_snapshot!(endpoints.render_styled(true));
}

#[test]
fn endpoint_rendering_distinguishes_empty_lifecycle_and_buffer_states() {
    use wormhole_core::model::EndpointStatus;

    assert_eq!(Vec::<wormhole_core::ActiveEndpoint>::new().render(), "no endpoints");
    let endpoints = vec![
        endpoint(EndpointStatus::Reconnecting, 3, 2, 1),
        endpoint(EndpointStatus::Offline, 0, 4, 1),
        endpoint(EndpointStatus::Error("failed".to_owned()), 0, 0, 0),
    ];
    let plain = endpoints.render();
    assert!(plain.contains("reconnecting"));
    assert!(plain.contains("replaying 3 buffered webhooks"));
    assert!(plain.contains("buffered: delivered=4 failed=1"));
    assert!(plain.contains("error"));
    let styled = endpoints.render_styled(true);
    assert!(styled.contains("\u{1b}["), "styled output contains ANSI escapes");
}

#[test]
fn status_closed_and_capture_human_contracts_include_operational_fields() {
    let status = crate::local_api::StatusResponse {
        version: "1.2.3".to_owned(),
        uptime_seconds: 7,
        pid: 42,
        services: 2,
        endpoints: 3,
    };
    assert_eq!(status.render(), "daemon 1.2.3 pid=42 uptime=7s services=2 endpoints=3");
    assert_eq!(crate::local_api::ClosedResponse { closed: true }.render(), "closed");
    assert_eq!(crate::local_api::ClosedResponse { closed: false }.render(), "not found");

    let capture = wormhole_core::CapturedRequest {
        id: uuid::Uuid::nil(),
        endpoint_id: None,
        bind_id: uuid::Uuid::nil(),
        method: "POST".to_owned(),
        uri: "/hook".to_owned(),
        headers: Vec::new(),
        body: vec![1, 2],
        body_truncated: false,
        response_status: None,
        response_headers: Vec::new(),
        response_body_prefix: vec![3],
        response_body_truncated: false,
        duration_ms: 9,
        delivery: "replay".to_owned(),
        captured_at: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    };
    let rendered = capture.render();
    assert!(rendered.contains("POST /hook"));
    assert!(
        rendered.contains("status=- duration=9ms delivery=replay request_bytes=2 response_bytes=1")
    );
    assert!(vec![capture].render().contains("POST\t/hook\t-"));
}

#[test]
fn utility_and_future_views_have_concise_human_contracts() {
    use std::net::{IpAddr, Ipv4Addr};

    assert_eq!(
        crate::future_api::ReplayResponse { status: 204, duration_ms: 7 }.render(),
        "status=204 duration=7ms"
    );
    assert_eq!(
        crate::share_api::ShareResponse {
            url: "https://share.example.test/path".to_owned(),
            expires_unix: 1_767_226_800,
        }
        .render(),
        "https://share.example.test/path"
    );
    assert_eq!(
        vec![wormhole_core::ifaces::IfaceAlias {
            alias: "loopback".to_owned(),
            iface: "lo0".to_owned(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }]
        .render(),
        "loopback\tlo0\t127.0.0.1"
    );
    let checks = vec![
        wormhole_core::model::DoctorCheck {
            name: "relay".to_owned(),
            healthy: true,
            detail: "reachable".to_owned(),
        },
        wormhole_core::model::DoctorCheck {
            name: "driver".to_owned(),
            healthy: false,
            detail: "missing".to_owned(),
        },
    ];
    assert_eq!(checks.render(), "relay\tok\treachable\ndriver\tfailed\tmissing");

    let remotes = vec![crate::api_types::RemoteView {
        name: "local".to_owned(),
        addr: "localhost:443".to_owned(),
        server_name: "localhost".to_owned(),
        identity: None,
    }];
    assert_eq!(remotes.render(), "local\tlocalhost:443\tlocalhost");
    assert_eq!(
        crate::utility_commands::KeyView {
            fingerprint: "SHA256:key".to_owned(),
            public_key: "public".to_owned(),
        }
        .render(),
        "SHA256:key\npublic"
    );
    assert_eq!(
        crate::utility_commands::RotationView {
            old_fingerprint: "old".to_owned(),
            new_fingerprint: "new".to_owned(),
            reminder: "update relays",
        }
        .render(),
        "old -> new\nupdate relays"
    );
    assert_eq!(
        crate::utility_commands::RemoteTestView { name: "local".to_owned(), latency_ms: 12 }
            .render(),
        "local\t12ms"
    );
    super::emit_error(&"failure", Some("recover"));
    super::emit_error(&"failure", None);
    assert!(super::spinner("hidden for JSON", true).is_none());
    super::finish_spinner(None);
}

fn endpoint(
    status: wormhole_core::model::EndpointStatus,
    pending: u32,
    delivered: u64,
    failed: u32,
) -> wormhole_core::ActiveEndpoint {
    wormhole_core::ActiveEndpoint {
        id: uuid::Uuid::now_v7(),
        service: "worker".to_owned(),
        driver: "cloudflare".to_owned(),
        urls: Vec::new(),
        status,
        buffered_delivered: delivered,
        buffered_pending: pending,
        buffered_failed: failed,
        since: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }
}
