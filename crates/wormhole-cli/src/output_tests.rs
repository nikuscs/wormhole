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
        since: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }];

    insta::assert_snapshot!(endpoints.render_styled(true));
}
