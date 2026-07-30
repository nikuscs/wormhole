use std::sync::Arc;

use camino::Utf8Path;
use proptest::prelude::*;
use tokio::io::AsyncWriteExt as _;
use wormhole_proto::{
    codec::ControlChannel,
    frames::ControlFrame,
    mux_runtime::{MuxEndpoint, MuxRole},
};
use wormholed::{
    authz::{AuthStore, KeyLimits},
    config::{LimitsConfig, PortRange},
    db::RelayDb,
    edge_tcp::TcpEdgeManager,
    registry::Registry,
    session::SessionActor,
    session_streams::DataOpener,
    state::AppState,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn arbitrary_control_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..128 * 1024)) {
        run_input(input);
    }

    #[test]
    fn mutated_valid_control_frame_sequences_never_panic(
        sequences in proptest::collection::vec((0_u8..5, any::<u128>(), any::<u64>()), 1..16),
        mutations in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..64)
    ) {
        let mut input = Vec::new();
        for (kind, id, seq) in sequences {
            let bind = uuid::Uuid::from_u128(id);
            let frame = match kind {
                0 => ControlFrame::Ping { seq },
                1 => ControlFrame::BindReady { bind },
                2 => ControlFrame::Unbind { bind, forget: seq.is_multiple_of(2) },
                3 => ControlFrame::ForgetReservation { reservation: bind },
                _ => ControlFrame::AckBuffered { bind, seq },
            };
            let payload = serde_json::to_vec(&frame).expect("frame");
            input.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            input.extend_from_slice(&payload);
        }
        for (index, value) in mutations {
            let length = input.len();
            input[index % length] ^= value;
        }
        run_input(input);
    }
}

fn run_input(input: Vec<u8>) {
    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(async move {
        let directory = tempfile::tempdir().expect("data directory");
        let data_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
        let database = Arc::new(RelayDb::open(data_dir).expect("database"));
        let registry = Arc::new(Registry::new(
            vec!["fuzz.example".to_owned()],
            Some(8443),
            8443,
            PortRange { start: 10_000, end: 10_010 },
        ));
        let limits = LimitsConfig::default();
        let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
        let state = Arc::new(
            AppState::new(
                registry,
                database,
                Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("bind IP"))),
                auth,
                limits,
            )
            .expect("state"),
        );
        let (endpoint, _network, _outbound) = MuxEndpoint::spawn(MuxRole::Server);
        let capacity = input.len().saturating_add(2 * 1024 * 1024).max(2 * 1024 * 1024);
        let (mut writer, reader) = tokio::io::duplex(capacity);
        let session = tokio::spawn(
            SessionActor::new(
                ControlChannel::new(reader),
                DataOpener::Mux(endpoint.opener),
                state,
                "fuzz-key".to_owned(),
                KeyLimits { max_binds: 8, max_sessions: 1, max_streams: 8 },
            )
            .run(),
        );
        let _written = writer.write_all(&input).await;
        let _closed = writer.shutdown().await;
        match tokio::time::timeout(std::time::Duration::from_secs(1), session).await {
            Ok(Ok(_session_result)) => {}
            Ok(Err(error)) => panic!("session handler panicked: {error}"),
            Err(error) => panic!("session handler hung: {error}"),
        }
    });
}
