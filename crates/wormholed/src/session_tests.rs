use std::sync::Arc;

use tempfile::tempdir;
use uuid::Uuid;
use wormhole_proto::{
    codec::ControlChannel,
    frames::{BindSpec, BufferPolicy, ControlFrame, EdgeAuth, EventKind, Persistence},
    mux_runtime::{MuxEndpoint, MuxRole},
};

use super::{SessionActor, SessionError, build_auth_verifier};
use crate::{
    authz::{AuthStore, KeyLimits},
    buffer::BufferedRequest,
    config::{LimitsConfig, PortRange, WormholedConfig},
    db::{BufferQuotas, RelayDb},
    edge_tcp::TcpEdgeManager,
    registry::{BindState, SessionCommand},
    session_streams::DataOpener,
    state::AppState,
};

#[test]
fn persisted_auth_contains_only_verification_material() {
    let verifier = build_auth_verifier(&EdgeAuth {
        basic: Some("agent:secret".to_owned()),
        bearer: Some("bearer-secret".to_owned()),
        link_key: Some("bGluay1rZXk=".to_owned()),
    })
    .expect("auth verifier must build");

    assert!(
        verifier.basic_argon2.as_deref().is_some_and(|value| {
            value.starts_with("agent:$argon2") && !value.contains("secret")
        })
    );
    assert_ne!(verifier.bearer_sha256.as_deref(), Some("bearer-secret"));
    assert_eq!(verifier.link_hmac_key.as_deref(), Some("bGluay1rZXk="));
}

#[test]
fn first_wave_persisted_auth_contains_only_verification_material() {
    let verifier = build_auth_verifier(&EdgeAuth {
        basic: Some("agent:secret".to_owned()),
        bearer: Some("bearer-secret".to_owned()),
        link_key: Some("bGluay1rZXk=".to_owned()),
    })
    .expect("auth verifier must build");

    assert!(
        verifier.basic_argon2.as_deref().is_some_and(|value| {
            value.starts_with("agent:$argon2") && !value.contains("secret")
        })
    );
    assert_ne!(verifier.bearer_sha256.as_deref(), Some("bearer-secret"));
    assert_eq!(verifier.link_hmac_key.as_deref(), Some("bGluay1rZXk="));
    assert!(
        build_auth_verifier(&EdgeAuth {
            basic: Some("missing-separator".to_owned()),
            bearer: None,
            link_key: None,
        })
        .is_err()
    );
}

#[test]
fn malformed_basic_auth_is_rejected_and_empty_auth_is_valid() {
    let error = build_auth_verifier(&EdgeAuth {
        basic: Some("missing-password-separator".to_owned()),
        bearer: None,
        link_key: None,
    })
    .expect_err("malformed basic auth");
    assert!(matches!(error, SessionError::Protocol(_)));

    let empty = build_auth_verifier(&EdgeAuth { basic: None, bearer: None, link_key: None })
        .expect("empty verifier");
    assert!(empty.basic_argon2.is_none());
    assert!(empty.bearer_sha256.is_none());
    assert!(empty.link_hmac_key.is_none());
}

fn state() -> (tempfile::TempDir, Arc<AppState>) {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = Arc::new(RelayDb::open(path).expect("database"));
    let limits = LimitsConfig::default();
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
    let registry = Arc::new(crate::registry::Registry::new(
        vec!["tun.example.com".to_owned()],
        Some(8443),
        443,
        PortRange { start: 10_000, end: 10_001 },
    ));
    let tcp = Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP")));
    let state =
        Arc::new(AppState::new(registry, database, tcp, auth, limits).expect("application state"));
    (directory, state)
}

fn actor(
    state: Arc<AppState>,
    fingerprint: &str,
    limits: KeyLimits,
) -> (ControlChannel<tokio::io::DuplexStream>, tokio::task::JoinHandle<Result<(), SessionError>>) {
    let (server, server_network, mut server_outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let (client, client_network, mut client_outbound) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(async move {
        while let Some(frame) = server_outbound.recv().await {
            if client_network.send(frame).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = client_outbound.recv().await {
            if server_network.send(frame).await.is_err() {
                return;
            }
        }
    });
    let task = tokio::spawn(
        SessionActor::new(
            ControlChannel::new(server.control),
            DataOpener::Mux(server.opener),
            state,
            fingerprint.to_owned(),
            limits,
        )
        .run(),
    );
    (ControlChannel::new(client.control), task)
}

fn http_spec(persist: Persistence, buffer: Option<BufferPolicy>) -> BindSpec {
    BindSpec::Http {
        host: Some("hook".to_owned()),
        auto_host: false,
        domain: None,
        persist,
        buffer,
        auth: None,
    }
}

async fn bind_endpoint(
    channel: &mut ControlChannel<tokio::io::DuplexStream>,
    spec: BindSpec,
    reservation: Option<Uuid>,
) -> (Uuid, Option<Uuid>) {
    let request = Uuid::now_v7();
    channel.send(&ControlFrame::Bind { request, spec, reservation }).await.expect("bind frame");
    let ControlFrame::Bound { request: echoed, bind, reservation, .. } =
        channel.recv().await.expect("bound frame")
    else {
        panic!("expected bound frame");
    };
    assert_eq!(echoed, request);
    (bind, reservation)
}

#[tokio::test]
async fn temporary_bind_activates_pings_and_unbinds() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 2, max_sessions: 1, max_streams: 2 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);

    channel.send(&ControlFrame::Ping { seq: 7 }).await.expect("ping");
    assert_eq!(channel.recv().await.expect("pong"), ControlFrame::Pong { seq: 7 });
    let (bind, reservation) =
        bind_endpoint(&mut channel, http_spec(Persistence::Temporary, None), None).await;
    assert!(reservation.is_none());
    assert_eq!(state.counts("owner").1, 1);
    channel.send(&ControlFrame::BindReady { bind }).await.expect("ready");
    assert_eq!(channel.recv().await.expect("active"), ControlFrame::BindActive { bind });
    assert_eq!(state.registry.get_bind(bind).expect("bind").state(), BindState::Online);
    channel.send(&ControlFrame::Unbind { bind, forget: false }).await.expect("unbind");
    assert_eq!(channel.recv().await.expect("unbound"), ControlFrame::Unbound { bind });
    assert!(state.registry.get_bind(bind).is_none());
    assert_eq!(state.counts("owner").1, 0);
    drop(channel);
    task.await.expect("actor task").expect("actor result");
}

#[tokio::test]
async fn persistent_bind_disconnects_reclaims_and_forgets_reservation() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 2, max_sessions: 1, max_streams: 2 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);
    let spec = http_spec(Persistence::Persistent, None);
    let (bind, reservation) = bind_endpoint(&mut channel, spec.clone(), None).await;
    let reservation = reservation.expect("reservation");
    assert!(state.database.get_bind(bind).expect("persisted bind").is_some());

    channel.send(&ControlFrame::Unbind { bind, forget: false }).await.expect("disconnect");
    assert_eq!(channel.recv().await.expect("unbound"), ControlFrame::Unbound { bind });
    assert_eq!(state.registry.get_bind(bind).expect("offline bind").state(), BindState::Offline);
    let (reclaimed, echoed) = bind_endpoint(&mut channel, spec, Some(reservation)).await;
    assert_eq!((reclaimed, echoed), (bind, Some(reservation)));
    assert_eq!(state.counts("owner").1, 1);

    channel.send(&ControlFrame::ForgetReservation { reservation }).await.expect("forget");
    assert_eq!(
        channel.recv().await.expect("forgot"),
        ControlFrame::ForgotReservation { reservation }
    );
    assert!(state.registry.get_bind(bind).is_none());
    assert!(state.database.get_bind(bind).expect("database").is_none());
    assert_eq!(state.counts("owner").1, 0);
    drop(channel);
    task.await.expect("actor task").expect("actor result");
}

#[tokio::test]
async fn buffered_ack_nack_and_status_commands_update_persistence() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 2, max_sessions: 1, max_streams: 2 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);
    let policy = BufferPolicy { max_requests: 4, max_body_bytes: 1024, ttl_secs: 60 };
    let (bind, _) =
        bind_endpoint(&mut channel, http_spec(Persistence::Persistent, Some(policy)), None).await;
    let enqueue = |body: &[u8]| {
        state.database.enqueue_buffered(
            bind,
            "owner",
            BufferedRequest {
                v: 1,
                method: "POST".to_owned(),
                uri: "/hook".to_owned(),
                http_version: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
                body: body.to_vec(),
                seq: 0,
                received_at: jiff::Timestamp::now(),
            },
            BufferQuotas { max_requests: 4, ttl_secs: 60, key_bytes: 4096, total_bytes: 4096 },
        )
    };
    let first = enqueue(b"first").expect("first");
    assert!(state.claim_buffered(bind, first));
    channel.send(&ControlFrame::AckBuffered { bind, seq: first }).await.expect("ACK");
    tokio::task::yield_now().await;
    assert_eq!(state.database.buffered_counts(bind).expect("counts"), (0, 0));

    let second = enqueue(b"second").expect("second");
    assert!(state.claim_buffered(bind, second));
    channel
        .send(&ControlFrame::NackBuffered {
            bind,
            seq: second,
            reason: "target rejected".to_owned(),
        })
        .await
        .expect("NACK");
    tokio::task::yield_now().await;
    assert_eq!(state.database.buffered_counts(bind).expect("counts"), (0, 1));

    let session = state.registry.get_bind(bind).expect("bind").session().expect("session");
    session
        .send(SessionCommand::BufferedStatus { bind, pending: 3, failed: 1 })
        .await
        .expect("status command");
    assert_eq!(
        channel.recv().await.expect("buffer status"),
        ControlFrame::BufferedStatus { bind, pending: 3, failed: 1 }
    );
    let (acknowledged, acknowledgement) = tokio::sync::oneshot::channel();
    session.send(SessionCommand::RemoveBind { bind, acknowledged }).await.expect("remove command");
    assert!(acknowledgement.await.expect("acknowledgement"));
    assert_eq!(state.counts("owner").1, 0);
    drop(channel);
    task.await.expect("actor task").expect("actor result");
}

#[tokio::test]
async fn bind_limits_protocol_errors_and_shutdown_are_reported() {
    let (_directory, state) = state();
    assert!(state.try_add_bind("limited", 1));
    let limits = KeyLimits { max_binds: 1, max_sessions: 1, max_streams: 1 };
    let (mut channel, task) = actor(Arc::clone(&state), "limited", limits);
    let request = Uuid::now_v7();
    channel
        .send(&ControlFrame::Bind {
            request,
            spec: http_spec(Persistence::Temporary, None),
            reservation: None,
        })
        .await
        .expect("bind");
    assert!(matches!(
        channel.recv().await.expect("bind error"),
        ControlFrame::BindError { request: echoed, reason } if echoed == request && reason.contains("limit")
    ));
    channel.send(&ControlFrame::Pong { seq: 1 }).await.expect("unexpected frame");
    let error = task.await.expect("actor task").expect_err("protocol error");
    assert!(matches!(error, SessionError::Protocol(_)));

    let (_shutdown_directory, shutdown_state) = super::tests::state();
    shutdown_state.begin_shutdown();
    let (mut shutdown_channel, shutdown_task) = actor(shutdown_state, "owner", limits);
    assert!(matches!(
        shutdown_channel.recv().await.expect("shutdown event"),
        ControlFrame::Event { kind: EventKind::Shutdown, .. }
    ));
    shutdown_task.await.expect("shutdown task").expect("shutdown actor");
}

#[tokio::test]
async fn closed_session_cleans_temporary_and_disconnects_persistent_binds() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 3, max_sessions: 1, max_streams: 1 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);
    let (temporary, _) =
        bind_endpoint(&mut channel, http_spec(Persistence::Temporary, None), None).await;
    let (persistent, _) = bind_endpoint(
        &mut channel,
        BindSpec::Http {
            host: Some("saved".to_owned()),
            auto_host: false,
            domain: None,
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
        },
        None,
    )
    .await;
    drop(channel);
    task.await.expect("actor task").expect("actor result");

    assert!(state.registry.get_bind(temporary).is_none());
    assert_eq!(
        state.registry.get_bind(persistent).expect("persistent").state(),
        BindState::Offline
    );
    assert_eq!(state.counts("owner").1, 1);
}

fn session_fixture() -> (tempfile::TempDir, Arc<AppState>, KeyLimits) {
    let directory = tempdir().expect("temporary directory");
    let root = camino::Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let config_path = root.join("wormholed.toml");
    WormholedConfig::initialize(&config_path).expect("initialize config");
    let config = WormholedConfig::load(&config_path).expect("load config");
    let database = Arc::new(crate::db::RelayDb::open(&config.server.data_dir).expect("database"));
    let auth = Arc::new(crate::authz::AuthStore::new(
        Arc::clone(&database),
        KeyLimits::from(&config.limits),
    ));
    let registry = Arc::new(crate::registry::Registry::new(
        config.server.domains,
        config.server.public_https_port,
        443,
        config.tcp.port_range,
    ));
    let tcp = Arc::new(crate::edge_tcp::TcpEdgeManager::new(config.server.https_addr.ip()));
    let state = Arc::new(
        AppState::new(registry, database, tcp, auth, config.limits.clone()).expect("state"),
    );
    (directory, state, KeyLimits::from(&config.limits))
}

#[tokio::test]
async fn session_ping_and_shutdown_follow_control_protocol() {
    let (_directory, state, limits) = session_fixture();
    let (relay_io, client_io) = tokio::io::duplex(4096);
    let (endpoint, _network, _outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let task = tokio::spawn(
        SessionActor::new(
            ControlChannel::new(relay_io),
            DataOpener::Mux(endpoint.opener),
            Arc::clone(&state),
            "WH256:test".to_owned(),
            limits,
        )
        .run(),
    );
    let mut client = ControlChannel::new(client_io);

    client.send(&ControlFrame::Ping { seq: 17 }).await.expect("ping");
    assert_eq!(client.recv().await.expect("pong"), ControlFrame::Pong { seq: 17 });
    state.begin_shutdown();
    assert_eq!(
        client.recv().await.expect("shutdown event"),
        ControlFrame::Event { kind: EventKind::Shutdown, msg: "relay shutting down".to_owned() }
    );
    task.await.expect("session task").expect("clean shutdown");
}

#[tokio::test]
async fn already_shutting_down_session_emits_event_without_reading_client() {
    let (_directory, state, limits) = session_fixture();
    state.begin_shutdown();
    let (relay_io, client_io) = tokio::io::duplex(4096);
    let (endpoint, _network, _outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let task = tokio::spawn(
        SessionActor::new(
            ControlChannel::new(relay_io),
            DataOpener::Mux(endpoint.opener),
            state,
            "WH256:test".to_owned(),
            limits,
        )
        .run(),
    );
    let mut client = ControlChannel::new(client_io);

    assert!(matches!(
        client.recv().await.expect("shutdown event"),
        ControlFrame::Event { kind: EventKind::Shutdown, .. }
    ));
    task.await.expect("session task").expect("clean shutdown");
}

#[tokio::test]
async fn session_commands_enforce_stream_limits_remove_unknown_and_shutdown() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 2, max_sessions: 1, max_streams: 0 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);
    let (bind, _) =
        bind_endpoint(&mut channel, http_spec(Persistence::Temporary, None), None).await;
    channel.send(&ControlFrame::BindReady { bind }).await.expect("ready");
    assert_eq!(channel.recv().await.expect("active"), ControlFrame::BindActive { bind });
    let session = state.registry.get_bind(bind).expect("bind").session().expect("session");

    let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
    drop(body_tx);
    let (reply, response) = tokio::sync::oneshot::channel();
    session
        .send(SessionCommand::OpenHttp {
            header: wormhole_proto::frames::StreamHeader::Http {
                bind,
                peer: "127.0.0.1:1".parse().expect("peer"),
                request: wormhole_proto::frames::HttpRequestHead {
                    method: "GET".to_owned(),
                    uri: "/".to_owned(),
                    version: "HTTP/1.1".to_owned(),
                    headers: Vec::new(),
                },
                buffered: None,
            },
            body: body_rx,
            upgrade: false,
            reply,
        })
        .await
        .expect("HTTP command");
    assert_eq!(
        response.await.expect("HTTP response").expect_err("stream limit"),
        "session stream limit reached"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let connect = tokio::net::TcpStream::connect(listener.local_addr().expect("address"));
    let (public, _) = tokio::join!(connect, listener.accept());
    session
        .send(SessionCommand::OpenTcp {
            header: wormhole_proto::frames::StreamHeader::Tcp {
                bind,
                peer: "127.0.0.1:2".parse().expect("peer"),
            },
            stream: public.expect("public stream"),
        })
        .await
        .expect("TCP command");
    let (acknowledged, acknowledgement) = tokio::sync::oneshot::channel();
    session
        .send(SessionCommand::RemoveBind { bind: Uuid::now_v7(), acknowledged })
        .await
        .expect("remove command");
    assert!(!acknowledgement.await.expect("remove acknowledgement"));
    session.send(SessionCommand::Shutdown).await.expect("shutdown command");
    assert!(matches!(
        channel.recv().await.expect("shutdown event"),
        ControlFrame::Event { kind: EventKind::Shutdown, .. }
    ));
    task.await.expect("actor task").expect("shutdown actor");
    assert!(state.registry.get_bind(bind).is_none());
}

#[tokio::test]
async fn allocation_errors_forget_missing_and_persistent_deletion_are_transactional() {
    let (_directory, state) = state();
    let limits = KeyLimits { max_binds: 2, max_sessions: 1, max_streams: 1 };
    let (mut channel, task) = actor(Arc::clone(&state), "owner", limits);
    let request = Uuid::now_v7();
    channel
        .send(&ControlFrame::Bind {
            request,
            spec: BindSpec::Http {
                host: Some("-invalid".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Temporary,
                buffer: None,
                auth: None,
            },
            reservation: None,
        })
        .await
        .expect("invalid bind");
    assert!(matches!(
        channel.recv().await.expect("bind error"),
        ControlFrame::BindError { request: echoed, .. } if echoed == request
    ));
    assert_eq!(state.counts("owner").1, 0);

    let (bind, _) =
        bind_endpoint(&mut channel, http_spec(Persistence::Persistent, None), None).await;
    channel.send(&ControlFrame::Unbind { bind, forget: true }).await.expect("forget bind");
    assert_eq!(channel.recv().await.expect("unbound"), ControlFrame::Unbound { bind });
    assert!(state.registry.get_bind(bind).is_none());
    assert!(state.database.get_bind(bind).expect("database").is_none());
    let missing = Uuid::now_v7();
    channel
        .send(&ControlFrame::ForgetReservation { reservation: missing })
        .await
        .expect("forget missing");
    assert_eq!(
        channel.recv().await.expect("forgot missing"),
        ControlFrame::ForgotReservation { reservation: missing }
    );

    channel
        .send(&ControlFrame::AckBuffered { bind: Uuid::now_v7(), seq: 1 })
        .await
        .expect("invalid buffered result");
    assert!(matches!(
        task.await.expect("actor task").expect_err("protocol error"),
        SessionError::Protocol(_)
    ));
}
