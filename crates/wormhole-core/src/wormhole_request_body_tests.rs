use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWriteExt as _, ReadBuf};

use super::{request_body, request_body_with_prefix, retain_request_body};
use crate::wormhole_stream::BoxRead;

#[tokio::test]
async fn retention_distinguishes_replayable_and_streaming_bodies() {
    let replayable = reader(b"small").await;
    let (retained, remainder, complete) =
        retain_request_body(replayable, 16, None).await.expect("retain complete body");
    assert_eq!(retained, b"small");
    assert!(remainder.is_none());
    assert!(complete);

    let streaming = reader(b"body larger than limit").await;
    let (retained, remainder, complete) =
        retain_request_body(streaming, 4, None).await.expect("retain prefix");
    assert_eq!(retained, b"body larger than limit");
    assert!(remainder.is_some());
    assert!(!complete);
}

#[tokio::test]
async fn retained_and_live_prefix_are_forwarded_in_order() {
    let body = request_body_with_prefix(b"retained-".to_vec(), reader(b"live").await, None);
    let collected = body.collect().await.expect("collect body").to_bytes();
    assert_eq!(collected, b"retained-live"[..]);
}

#[tokio::test]
async fn request_body_handles_regular_upgrade_and_read_failure_paths() {
    let (body, upgraded) = request_body(reader(b"payload").await, false, None);
    assert!(upgraded.is_none());
    assert_eq!(body.collect().await.expect("collect body").to_bytes(), b"payload"[..]);

    let (body, upgraded) = request_body(reader(b"raw stream").await, true, None);
    assert!(body.collect().await.expect("empty upgrade body").to_bytes().is_empty());
    let mut upgraded = upgraded.expect("upgraded stream retained");
    let mut raw = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut upgraded, &mut raw)
        .await
        .expect("read upgraded stream");
    assert_eq!(raw, b"raw stream");

    let (body, _) = request_body(Box::new(FailingReader), false, None);
    let error = body.collect().await.expect_err("read failure surfaces");
    assert!(error.to_string().contains("fixture read failure"));
}

#[tokio::test]
async fn retention_surfaces_public_read_failures() {
    let result = retain_request_body(Box::new(FailingReader), 16, None).await;
    let Err(error) = result else { panic!("read failure must surface") };
    assert!(error.to_string().contains("fixture read failure"));
}

async fn reader(bytes: &'static [u8]) -> BoxRead {
    let (mut writer, reader) = tokio::io::duplex(64);
    writer.write_all(bytes).await.expect("write fixture");
    writer.shutdown().await.expect("finish fixture");
    Box::new(reader)
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("fixture read failure")))
    }
}
