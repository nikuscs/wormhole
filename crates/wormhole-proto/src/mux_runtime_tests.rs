use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

use super::{MuxEndpoint, MuxRole, reset_network_frame};
use crate::{
    codec::{ControlChannel, read_response_head, read_stream_header, write_response_head},
    frames::{
        ControlFrame, EventKind, HeaderField, HttpRequestHead, HttpResponseHead, StreamHeader,
    },
    mux::{Direction, MuxControl, WsMessage},
};

#[tokio::test]
async fn stalled_data_channel_does_not_block_control_channel() {
    let (mut server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    let mut server_stream = server.opener.open(header).await.expect("open");
    let mut stalled = client.incoming.recv().await.expect("incoming");
    let _header = read_stream_header(&mut stalled).await.expect("header");
    let writer = tokio::spawn(async move {
        let payload = vec![7_u8; 1024 * 1024];
        let _result = server_stream.write_all(&payload).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    server.control.write_all(b"control").await.expect("control write");
    let mut received = [0_u8; 7];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.control.read_exact(&mut received),
    )
    .await
    .expect("control must not starve")
    .expect("control read");
    assert_eq!(&received, b"control");
    writer.abort();
}

#[tokio::test]
async fn initial_window_accepts_many_small_frames_without_resetting() {
    let (mut endpoint, network, mut outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let channel = 1;
    let open = MuxControl::Open {
        channel,
        header: StreamHeader::Tcp {
            bind: Uuid::now_v7(),
            peer: "127.0.0.1:1234".parse().expect("peer"),
        },
    };
    let mut control = vec![super::CONTROL_MUX];
    control.extend_from_slice(&serde_json::to_vec(&open).expect("open"));
    network
        .send(WsMessage { channel: 0, payload: control }.encode().expect("wire"))
        .await
        .expect("inject open");
    let mut stream = endpoint.incoming.recv().await.expect("incoming");
    let _header = read_stream_header(&mut stream).await.expect("header");
    let _ack = outbound.recv().await.expect("ack");
    tokio::spawn(async move { while outbound.recv().await.is_some() {} });
    let frame = vec![7_u8; 4096];
    for _ in 0..64 {
        network
            .send(WsMessage { channel, payload: frame.clone() }.encode().expect("wire"))
            .await
            .expect("inject data");
    }
    let mut received = vec![0_u8; 64 * frame.len()];
    tokio::time::timeout(std::time::Duration::from_secs(1), stream.read_exact(&mut received))
        .await
        .expect("small frames must not stall")
        .expect("small frames must not reset");
    assert!(received.iter().all(|byte| *byte == 7));
}

#[tokio::test]
async fn large_stream_flushes_before_fin() {
    let (server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    let mut receiver = server.opener.open(header).await.expect("open");
    let mut sender = client.incoming.recv().await.expect("incoming");
    let _header = read_stream_header(&mut sender).await.expect("header");
    let expected = vec![9_u8; 2 * 1024 * 1024];
    let sent = expected.clone();
    let writer = tokio::spawn(async move {
        write_response_head(
            &mut sender,
            &HttpResponseHead { status: 200, version: "HTTP/1.1".to_owned(), headers: Vec::new() },
        )
        .await
        .expect("response head");
        sender.write_all(&sent).await.expect("write large stream");
        sender.shutdown().await.expect("finish large stream");
    });
    let _response = read_response_head(&mut receiver).await.expect("response head");
    let mut payload = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), receiver.read_to_end(&mut payload))
        .await
        .expect("large stream timeout")
        .expect("read large stream");
    writer.await.expect("writer");
    assert_eq!(payload, expected);
}

#[tokio::test]
async fn malformed_mux_control_variants_close_without_leaking() {
    let bad_parity = MuxControl::Open {
        channel: 2,
        header: StreamHeader::Tcp {
            bind: Uuid::now_v7(),
            peer: "127.0.0.1:1234".parse().expect("peer"),
        },
    };
    let mut parity_payload = vec![super::CONTROL_MUX];
    parity_payload.extend_from_slice(&serde_json::to_vec(&bad_parity).expect("control"));
    for payload in [Vec::new(), vec![9], parity_payload] {
        let (endpoint, network, mut outbound) = MuxEndpoint::spawn(MuxRole::Server);
        network
            .send(WsMessage { channel: 0, payload }.encode().expect("wire"))
            .await
            .expect("inject");
        drop(endpoint);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(outbound.recv().await.is_none());
    }
}

#[tokio::test]
async fn unknown_fin_window_and_reset_do_not_close_control() {
    let (mut endpoint, network, mut outbound) = MuxEndpoint::spawn(MuxRole::Server);
    for control in [
        MuxControl::Fin { channel: 44, direction: Direction::Send },
        MuxControl::Fin { channel: 44, direction: Direction::Receive },
        MuxControl::Window { channel: 44, bytes: 1024 },
        MuxControl::Reset { channel: 44 },
    ] {
        let mut payload = vec![super::CONTROL_MUX];
        payload.extend_from_slice(&serde_json::to_vec(&control).expect("control"));
        network
            .send(WsMessage { channel: 0, payload }.encode().expect("wire"))
            .await
            .expect("inject");
    }
    endpoint.control.write_all(b"live").await.expect("control write");
    let message = outbound.recv().await.expect("control remains live");
    assert_eq!(WsMessage::decode(&message).expect("decode").channel, 0);
}

#[tokio::test]
async fn malformed_control_closes_actor_and_releases_tasks() {
    for role in [MuxRole::Client, MuxRole::Server] {
        let (mut endpoint, network, mut outbound) = MuxEndpoint::spawn(role);
        network.send(Vec::new()).await.expect("inject malformed");
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let header = StreamHeader::Tcp {
            bind: Uuid::now_v7(),
            peer: "127.0.0.1:1234".parse().expect("peer"),
        };
        assert!(endpoint.opener.open(header).await.is_err());
        assert!(outbound.recv().await.is_none());
        let mut control = [0_u8; 1];
        assert_eq!(endpoint.control.read(&mut control).await.expect("control eof"), 0);
    }
}

#[tokio::test]
async fn unknown_and_oversized_control_channels_are_rejected() {
    let (endpoint, network, mut outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let unknown =
        crate::mux::WsMessage { channel: 99, payload: vec![1] }.encode().expect("unknown frame");
    network.send(unknown).await.expect("inject unknown");
    let reset = outbound.recv().await.expect("reset unknown");
    assert_eq!(crate::mux::WsMessage::decode(&reset).expect("decode reset").channel, 0);
    let mut oversized_control = 0_u32.to_be_bytes().to_vec();
    oversized_control.resize(crate::mux::MAX_PAYLOAD + 5, 0);
    network.send(oversized_control).await.expect("inject oversized control");
    drop(endpoint);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(outbound.recv().await.is_none());
}

#[tokio::test]
async fn oversized_data_resets_only_its_channel() {
    let (mut server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    let oversized_in = server_in.clone();
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    let mut server_stream = server.opener.open(header).await.expect("open");
    let mut client_stream = client.incoming.recv().await.expect("incoming");
    let _header = read_stream_header(&mut client_stream).await.expect("header");
    let mut oversized = 2_u32.to_be_bytes().to_vec();
    oversized.resize(crate::mux::MAX_PAYLOAD + 5, 7);
    oversized_in.send(oversized).await.expect("inject oversized");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server_stream.read_to_end(&mut Vec::new()),
    )
    .await
    .expect("reset closes channel")
    .expect("channel eof");
    client.control.write_all(b"ok").await.expect("control write");
    let mut control = [0_u8; 2];
    server.control.read_exact(&mut control).await.expect("control read");
    assert_eq!(&control, b"ok");
    assert!(reset_network_frame(0).is_err());
    assert!(reset_network_frame(2).is_ok());
}

#[tokio::test]
async fn dropped_readers_release_channels_after_crossed_fin() {
    let (server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    for _ in 0..40 {
        let mut sender = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.opener.open(header.clone()),
        )
        .await
        .expect("channel slot must be released")
        .expect("open");
        let mut dropped = client.incoming.recv().await.expect("incoming");
        let _header = read_stream_header(&mut dropped).await.expect("header");
        drop(dropped);
        let _write = sender.write_all(b"trigger dropped reader").await;
        drop(sender);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

#[tokio::test]
async fn remote_fin_after_application_drop_resets_only_its_channel() {
    let (mut server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    for _ in 0..40 {
        let mut server_stream = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.opener.open(header.clone()),
        )
        .await
        .expect("channel slot released")
        .expect("open");
        let mut dropped = client.incoming.recv().await.expect("incoming");
        let _header = read_stream_header(&mut dropped).await.expect("header");
        drop(dropped);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        server_stream.shutdown().await.expect("remote fin");
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    client.control.write_all(b"ok").await.expect("control write");
    let mut control = [0_u8; 2];
    server.control.read_exact(&mut control).await.expect("control read");
    assert_eq!(&control, b"ok");
}

#[tokio::test]
async fn channel_count_is_bounded_without_closing_control() {
    let (server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header =
        StreamHeader::Tcp { bind: Uuid::now_v7(), peer: "127.0.0.1:1234".parse().expect("peer") };
    let mut held = Vec::new();
    for _ in 0..super::MAX_STREAMS {
        held.push(server.opener.open(header.clone()).await.expect("within channel limit"));
        let mut incoming = client.incoming.recv().await.expect("incoming");
        let _header = read_stream_header(&mut incoming).await.expect("header");
        held.push(incoming);
    }
    assert_eq!(held.len(), 2 * super::MAX_STREAMS as usize);
    assert!(server.opener.open(header).await.is_err());
}

#[tokio::test]
async fn maximum_fragmented_control_frame_survives_mux() {
    let (server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let mut sender = ControlChannel::new(server.control);
    let mut receiver = ControlChannel::new(client.control);
    let empty = ControlFrame::Event { kind: EventKind::Info, msg: String::new() };
    let overhead = serde_json::to_vec(&empty).expect("encode empty frame").len();
    let frame =
        ControlFrame::Event { kind: EventKind::Info, msg: "x".repeat(1024 * 1024 - overhead) };
    assert_eq!(serde_json::to_vec(&frame).expect("encode max frame").len(), 1024 * 1024);
    sender.send(&frame).await.expect("maximum control send");
    let decoded = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
        .await
        .expect("large control must not stall")
        .expect("large control receive");
    assert_eq!(decoded, frame);
}

#[tokio::test]
async fn maximum_stream_header_survives_larger_control_envelope() {
    let (server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let mut header = StreamHeader::Http {
        bind: Uuid::now_v7(),
        peer: "127.0.0.1:1234".parse().expect("peer"),
        request: HttpRequestHead {
            method: "GET".to_owned(),
            uri: "/".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![HeaderField { name: "x-large".to_owned(), value_b64: String::new() }],
        },
        buffered: None,
    };
    let base = serde_json::to_vec(&header).expect("base header").len();
    let target = crate::mux::MAX_PAYLOAD;
    let StreamHeader::Http { request, .. } = &mut header else { unreachable!() };
    request.headers[0].value_b64 = "x".repeat(target - base);
    assert_eq!(serde_json::to_vec(&header).expect("maximum header").len(), target);

    let _sender = server.opener.open(header.clone()).await.expect("maximum header open");
    let mut receiver = client.incoming.recv().await.expect("incoming maximum header");
    assert_eq!(read_stream_header(&mut receiver).await.expect("maximum header read"), header);
}

#[tokio::test]
async fn server_open_round_trips_header_and_bidirectional_data() {
    let (mut server, server_in, mut server_out) = MuxEndpoint::spawn(MuxRole::Server);
    let (mut client, client_in, mut client_out) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(message) = server_out.recv().await {
            if client_in.send(message).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = client_out.recv().await {
            if server_in.send(message).await.is_err() {
                break;
            }
        }
    });
    let header = StreamHeader::Http {
        bind: Uuid::now_v7(),
        peer: "127.0.0.1:1234".parse().expect("peer"),
        request: HttpRequestHead {
            method: "GET".to_owned(),
            uri: "/".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
        },
        buffered: None,
    };
    let mut server_stream = server.opener.open(header.clone()).await.expect("open");
    let mut client_stream = client.incoming.recv().await.expect("incoming");
    assert_eq!(read_stream_header(&mut client_stream).await.expect("header"), header);
    server_stream.write_all(b"request").await.expect("server write");
    let mut request = [0_u8; 7];
    client_stream.read_exact(&mut request).await.expect("client read");
    assert_eq!(&request, b"request");
    client_stream.write_all(b"reply").await.expect("client write");
    let mut reply = [0_u8; 5];
    server_stream.read_exact(&mut reply).await.expect("server read");
    assert_eq!(&reply, b"reply");
    drop(server_stream);
    drop(client_stream);
    tokio::task::yield_now().await;
    let _second_server = server.opener.open(header.clone()).await.expect("second open");
    let mut second_client = client.incoming.recv().await.expect("second incoming");
    assert_eq!(read_stream_header(&mut second_client).await.expect("second header"), header);
    server.control.shutdown().await.expect("server control close");
    client.control.shutdown().await.expect("client control close");
}
