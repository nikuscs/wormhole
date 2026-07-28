use std::net::SocketAddr;

use tokio::io::{AsyncWriteExt, duplex};
use uuid::Uuid;

use super::{
    CONTROL_FRAME_LIMIT, ControlChannel, DATA_HEAD_LIMIT, read_response_head, read_stream_header,
    write_response_head, write_stream_header,
};
use crate::{
    ProtoError,
    frames::{ControlFrame, HeaderField, HttpRequestHead, HttpResponseHead, StreamHeader},
};

fn mixed_frames() -> Vec<ControlFrame> {
    (0..100)
        .map(
            |seq| {
                if seq % 2 == 0 { ControlFrame::Ping { seq } } else { ControlFrame::Pong { seq } }
            },
        )
        .collect()
}

#[tokio::test]
async fn control_channel_round_trips_mixed_frames() {
    let (client_io, server_io) = duplex(64 * 1024);
    let expected = mixed_frames();
    let sent = expected.clone();
    let sender = tokio::spawn(async move {
        let mut channel = ControlChannel::new(client_io);
        for frame in sent {
            channel.send(&frame).await.expect("control frame must send");
        }
    });
    let mut receiver = ControlChannel::new(server_io);

    for frame in expected {
        assert_eq!(receiver.recv().await.expect("control frame must arrive"), frame);
    }
    sender.await.expect("sender task must finish");
}

#[tokio::test]
async fn control_close_flushes_and_peer_observes_eof() {
    let (client_io, server_io) = duplex(1024);
    let mut sender = ControlChannel::new(client_io);
    let mut receiver = ControlChannel::new(server_io);
    sender.send(&ControlFrame::Ping { seq: 7 }).await.expect("send");
    sender.close().await.expect("close");
    assert!(matches!(receiver.recv().await, Ok(ControlFrame::Ping { seq: 7 })));
    assert!(matches!(receiver.recv().await, Err(ProtoError::Closed)));
}

#[tokio::test]
async fn oversized_control_frame_returns_explicit_error() {
    let (mut writer, reader) = duplex(16);
    let declared = u32::try_from(CONTROL_FRAME_LIMIT + 1).expect("limit fits u32");
    writer.write_all(&declared.to_be_bytes()).await.expect("prefix must write");
    let mut channel = ControlChannel::new(reader);

    let error = channel.recv().await.expect_err("oversized frame must fail");

    assert!(matches!(error, ProtoError::FrameTooLarge { limit } if limit == CONTROL_FRAME_LIMIT));
}

#[tokio::test]
async fn oversized_data_head_returns_explicit_error() {
    let (mut writer, mut reader) = duplex(16);
    let declared = u32::try_from(DATA_HEAD_LIMIT + 1).expect("limit fits u32");
    writer.write_all(&declared.to_be_bytes()).await.expect("prefix must write");

    let error = read_stream_header(&mut reader).await.expect_err("oversized head must fail");

    assert!(matches!(error, ProtoError::FrameTooLarge { limit } if limit == DATA_HEAD_LIMIT));
}

#[tokio::test]
async fn stream_and_response_heads_round_trip() {
    let peer = "127.0.0.1:32100".parse::<SocketAddr>().expect("valid peer");
    let stream = StreamHeader::Http {
        bind: Uuid::from_u128(1),
        peer,
        request: HttpRequestHead {
            method: "GET".to_owned(),
            uri: "/health".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
        },
        buffered: None,
    };
    let response = HttpResponseHead {
        status: 200,
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField {
            name: "content-length".to_owned(),
            value_b64: "MA==".to_owned(),
        }],
    };
    let (mut writer, mut reader) = duplex(4096);
    write_stream_header(&mut writer, &stream).await.expect("stream header must write");
    write_response_head(&mut writer, &response).await.expect("response head must write");

    assert_eq!(read_stream_header(&mut reader).await.expect("stream header must read"), stream);
    assert_eq!(read_response_head(&mut reader).await.expect("response head must read"), response);
}
