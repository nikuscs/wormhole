use proptest::{collection::vec, option, prelude::*, string::string_regex};
use tokio::{
    io::{AsyncWriteExt, duplex},
    runtime::{Builder, Runtime},
};
use uuid::Uuid;

use crate::{
    codec::ControlChannel,
    frames::{
        BindSpec, BufferPolicy, ControlFrame, DenyReason, EdgeAuth, EventKind, Limits, Persistence,
    },
};

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().expect("test runtime must build")
}

fn text() -> impl Strategy<Value = String> {
    string_regex("[a-zA-Z0-9._:/?&=-]{0,32}").expect("valid test regex")
}

fn identifier() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

fn persistence() -> impl Strategy<Value = Persistence> {
    any::<bool>().prop_map(|persistent| {
        if persistent { Persistence::Persistent } else { Persistence::Temporary }
    })
}

fn edge_auth() -> impl Strategy<Value = EdgeAuth> {
    (option::of(text()), option::of(text()), option::of(text()))
        .prop_map(|(basic, bearer, link_key)| EdgeAuth { basic, bearer, link_key })
}

fn buffer_policy() -> impl Strategy<Value = BufferPolicy> {
    (any::<u32>(), any::<u64>(), any::<u64>()).prop_map(
        |(max_requests, max_body_bytes, ttl_secs)| BufferPolicy {
            max_requests,
            max_body_bytes,
            ttl_secs,
        },
    )
}

fn bind_spec() -> impl Strategy<Value = BindSpec> {
    prop_oneof![
        (
            option::of(text()),
            option::of(text()),
            persistence(),
            option::of(buffer_policy()),
            option::of(edge_auth()),
        )
            .prop_map(|(host, domain, persist, buffer, auth)| BindSpec::Http {
                host,
                auto_host: false,
                domain,
                persist,
                buffer,
                auth,
            }),
        (option::of(any::<u16>()), persistence())
            .prop_map(|(remote_port, persist)| BindSpec::Tcp { remote_port, persist }),
    ]
}

fn deny_reason() -> impl Strategy<Value = DenyReason> {
    prop_oneof![
        Just(DenyReason::UnknownKey),
        Just(DenyReason::BadSignature),
        any::<u16>().prop_map(|expected| DenyReason::VersionMismatch { expected }),
        Just(DenyReason::KeyRevoked),
        Just(DenyReason::Limit),
    ]
}

fn event_kind() -> impl Strategy<Value = EventKind> {
    prop_oneof![
        Just(EventKind::Info),
        Just(EventKind::Warning),
        Just(EventKind::BufferedDelivery),
        Just(EventKind::Shutdown),
    ]
}

fn control_frame() -> impl Strategy<Value = ControlFrame> {
    prop_oneof![
        (any::<u16>(), text(), text(), option::of(text())).prop_map(
            |(proto, client, pubkey, invite)| ControlFrame::Hello { proto, client, pubkey, invite }
        ),
        (text(), text()).prop_map(|(nonce, server)| ControlFrame::Challenge { nonce, server }),
        text().prop_map(|signature| ControlFrame::Auth { signature }),
        (identifier(), any::<u32>(), any::<u32>(), option::of(text()), vec(text(), 0..4)).prop_map(
            |(session, max_binds, max_streams, motd, domains)| ControlFrame::Welcome {
                session,
                limits: Limits { max_binds, max_streams },
                motd,
                domains,
            }
        ),
        deny_reason().prop_map(|reason| ControlFrame::Denied { reason }),
        (identifier(), bind_spec(), option::of(identifier())).prop_map(
            |(request, spec, reservation)| ControlFrame::Bind { request, spec, reservation }
        ),
        (identifier(), any::<bool>())
            .prop_map(|(bind, forget)| ControlFrame::Unbind { bind, forget }),
        identifier().prop_map(|bind| ControlFrame::BindReady { bind }),
        (
            identifier(),
            identifier(),
            vec(text(), 0..3),
            persistence(),
            option::of(identifier()),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(
                |(request, bind, urls, persist, reservation, pending_buffered, failed_buffered)| {
                    ControlFrame::Bound {
                        request,
                        bind,
                        urls,
                        persist,
                        reservation,
                        pending_buffered,
                        failed_buffered,
                    }
                }
            ),
        (identifier(), text())
            .prop_map(|(request, reason)| ControlFrame::BindError { request, reason }),
        identifier().prop_map(|bind| ControlFrame::BindActive { bind }),
        (event_kind(), text()).prop_map(|(kind, msg)| ControlFrame::Event { kind, msg }),
        (identifier(), any::<u64>())
            .prop_map(|(bind, seq)| ControlFrame::AckBuffered { bind, seq }),
        (identifier(), any::<u64>(), text())
            .prop_map(|(bind, seq, reason)| { ControlFrame::NackBuffered { bind, seq, reason } }),
        any::<u64>().prop_map(|seq| ControlFrame::Ping { seq }),
        any::<u64>().prop_map(|seq| ControlFrame::Pong { seq }),
    ]
}

async fn round_trip(frame: &ControlFrame) -> ControlFrame {
    let (sender_io, receiver_io) = duplex(128 * 1024);
    let mut sender = ControlChannel::new(sender_io);
    let mut receiver = ControlChannel::new(receiver_io);
    sender.send(frame).await.expect("valid frame must send");
    receiver.recv().await.expect("valid frame must receive")
}

async fn decode_noise(bytes: &[u8]) {
    let capacity = bytes.len().saturating_add(8).max(8);
    let (mut writer, reader) = duplex(capacity);
    writer.write_all(bytes).await.expect("noise must write");
    writer.shutdown().await.expect("noise stream must close");
    let mut channel = ControlChannel::new(reader);
    let _result = channel.recv().await;
}

proptest! {
    #[test]
    fn prop_valid_control_frames_round_trip(frame in control_frame()) {
        let decoded = runtime().block_on(round_trip(&frame));
        prop_assert_eq!(decoded, frame);
    }

    #[test]
    fn prop_arbitrary_byte_noise_never_panics(bytes in vec(any::<u8>(), 0..100_000)) {
        runtime().block_on(decode_noise(&bytes));
    }
}
