use criterion::{Criterion, criterion_group, criterion_main};
use uuid::Uuid;
use wormhole_proto::frames::{ControlFrame, HeaderField, HttpRequestHead};

fn codec_benches(criterion: &mut Criterion) {
    let frame = ControlFrame::Ping { seq: 42 };
    criterion.bench_function("control frame encode/decode", |bencher| {
        bencher.iter(|| {
            let encoded = serde_json::to_vec(&frame).expect("encode");
            serde_json::from_slice::<ControlFrame>(&encoded).expect("decode")
        });
    });

    let head = HttpRequestHead {
        method: "POST".to_owned(),
        uri: format!("/hooks/{}", Uuid::nil()),
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField {
            name: "content-type".to_owned(),
            value_b64: "YXBwbGljYXRpb24vanNvbg==".to_owned(),
        }],
    };
    criterion.bench_function("HTTP head encode/decode", |bencher| {
        bencher.iter(|| {
            let encoded = serde_json::to_vec(&head).expect("encode");
            serde_json::from_slice::<HttpRequestHead>(&encoded).expect("decode")
        });
    });
}

criterion_group!(benches, codec_benches);
criterion_main!(benches);
