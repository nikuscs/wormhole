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
