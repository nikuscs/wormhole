use std::sync::{Arc, atomic::AtomicU32};

use super::EndpointHandle;
use crate::{driver::DriverEvent, model::ResolvedTarget, wormhole_conn::ConnCommand};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_util::sync::CancellationToken;

#[test]
fn buffered_counters_never_underflow_and_track_failures() {
    let handle = endpoint();
    assert!(matches!(
        handle.record_buffered_status(2, 1),
        DriverEvent::BufferedDelivery { pending: 2, failed: 1, delivered_delta: 0 }
    ));
    assert!(matches!(
        handle.record_buffered_result(true),
        DriverEvent::BufferedDelivery { pending: 1, failed: 1, delivered_delta: 1 }
    ));
    assert!(matches!(
        handle.record_buffered_result(false),
        DriverEvent::BufferedDelivery { pending: 0, failed: 2, delivered_delta: 0 }
    ));
    assert!(matches!(
        handle.record_buffered_result(false),
        DriverEvent::BufferedDelivery { pending: 0, failed: 3, delivered_delta: 0 }
    ));
}

fn endpoint() -> EndpointHandle {
    let (events, _) = mpsc::channel(1);
    let (_, forget) = watch::channel(false);
    let (commands, _) = mpsc::channel::<ConnCommand>(1);
    EndpointHandle {
        target: ResolvedTarget("127.0.0.1:1".parse().expect("target")),
        semaphore: Arc::new(Semaphore::new(1)),
        stop: CancellationToken::new(),
        forget,
        events,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 0,
        retry: None,
        buffered_pending: AtomicU32::new(0),
        buffered_failed: AtomicU32::new(0),
        commands,
    }
}
