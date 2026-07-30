use std::{fmt::Debug, net::SocketAddr};

use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use super::{
    BindSpec, BufferPolicy, ControlFrame, DenyReason, EdgeAuth, EventKind, HeaderField,
    HttpRequestHead, HttpResponseHead, Limits, Persistence, StreamHeader,
};

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn assert_round_trip<T>(value: &T)
where
    T: Debug + PartialEq + Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_vec(value).expect("frame must serialize");
    let decoded = serde_json::from_slice::<T>(&encoded).expect("frame must deserialize");
    assert_eq!(&decoded, value);
}

fn http_spec(persist: Persistence) -> BindSpec {
    BindSpec::Http {
        host: Some("web-fix-ui".to_owned()),
        auto_host: false,
        domain: Some("tun.example.com".to_owned()),
        persist,
        buffer: Some(BufferPolicy { max_requests: 25, max_body_bytes: 1_048_576, ttl_secs: 600 }),
        auth: Some(EdgeAuth {
            basic: Some("agent:secret".to_owned()),
            bearer: Some("token".to_owned()),
            link_key: Some("bGluay1rZXk=".to_owned()),
        }),
    }
}

#[test]
fn every_control_frame_variant_round_trips() {
    let session = id(1);
    let request = id(2);
    let bind = id(3);
    let reservation = id(4);
    let limits = Limits { max_binds: 8, max_streams: 64 };
    let frames = vec![
        ControlFrame::Hello {
            proto: 1,
            client: "wormhole-cli".to_owned(),
            pubkey: "cHVibGljLWtleQ==".to_owned(),
            invite: None,
        },
        ControlFrame::Challenge {
            nonce: "bm9uY2U=".to_owned(),
            server: "relay.example.com".to_owned(),
        },
        ControlFrame::Auth { signature: "c2lnbmF0dXJl".to_owned() },
        ControlFrame::Welcome {
            session,
            limits,
            motd: Some("hello".to_owned()),
            domains: vec!["tun.example.com".to_owned()],
        },
        ControlFrame::Denied { reason: DenyReason::UnknownKey },
        ControlFrame::Bind {
            request,
            spec: http_spec(Persistence::Persistent),
            reservation: Some(reservation),
        },
        ControlFrame::Unbind { bind, forget: true },
        ControlFrame::BindReady { bind },
        ControlFrame::Bound {
            request,
            bind,
            urls: vec!["https://web.tun.example.com".to_owned()],
            persist: Persistence::Persistent,
            reservation: Some(reservation),
            pending_buffered: 2,
            failed_buffered: 1,
        },
        ControlFrame::BindError { request, reason: "domain unavailable".to_owned() },
        ControlFrame::BindActive { bind },
        ControlFrame::Event { kind: EventKind::Info, msg: "connected".to_owned() },
        ControlFrame::AckBuffered { bind, seq: 7 },
        ControlFrame::NackBuffered { bind, seq: 8, reason: "target refused".to_owned() },
        ControlFrame::Ping { seq: 9 },
        ControlFrame::Pong { seq: 9 },
    ];

    for frame in frames {
        assert_round_trip(&frame);
    }
}

#[test]
fn welcome_from_older_relay_defaults_advertised_domains() {
    let encoded = format!(
        r#"{{"t":"welcome","session":"{}","limits":{{"max_binds":8,"max_streams":64}},"motd":null}}"#,
        id(1)
    );
    let decoded = serde_json::from_str::<ControlFrame>(&encoded).expect("legacy welcome");
    assert!(matches!(decoded, ControlFrame::Welcome { domains, .. } if domains.is_empty()));
}

#[test]
fn every_nested_enum_variant_round_trips() {
    let deny_reasons = [
        DenyReason::UnknownKey,
        DenyReason::BadSignature,
        DenyReason::VersionMismatch { expected: 1 },
        DenyReason::KeyRevoked,
        DenyReason::Limit,
    ];
    let event_kinds =
        [EventKind::Info, EventKind::Warning, EventKind::BufferedDelivery, EventKind::Shutdown];
    let specs = [
        http_spec(Persistence::Temporary),
        BindSpec::Tcp { remote_port: Some(8443), persist: Persistence::Persistent },
    ];

    for reason in deny_reasons {
        assert_round_trip(&reason);
    }
    for kind in event_kinds {
        assert_round_trip(&kind);
    }
    for spec in specs {
        assert_round_trip(&spec);
    }
}

#[test]
fn every_stream_header_variant_round_trips() {
    let peer = "127.0.0.1:41234".parse::<SocketAddr>().expect("valid socket address");
    let request = HttpRequestHead {
        method: "POST".to_owned(),
        uri: "/hooks?event=push".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField { name: "x-binary".to_owned(), value_b64: "/wA=".to_owned() }],
    };
    let headers = [
        StreamHeader::Http { bind: id(10), peer, request, buffered: Some(42) },
        StreamHeader::Tcp { bind: id(11), peer },
    ];

    for header in headers {
        assert_round_trip(&header);
    }
}

#[test]
fn response_head_round_trips() {
    let response = HttpResponseHead {
        status: 202,
        version: "HTTP/1.1".to_owned(),
        headers: vec![HeaderField {
            name: "content-type".to_owned(),
            value_b64: "YXBwbGljYXRpb24vanNvbg==".to_owned(),
        }],
    };

    assert_round_trip(&response);
}
