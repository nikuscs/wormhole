//! Shared client connection endpoint state.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use tokio::sync::{Semaphore, mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    driver::DriverEvent,
    model::{ResolvedTarget, RetryPolicy},
    wormhole_conn::ConnCommand,
};

pub struct EndpointHandle {
    pub target: ResolvedTarget,
    pub semaphore: Arc<Semaphore>,
    pub stop: CancellationToken,
    pub forget: watch::Receiver<bool>,
    pub events: mpsc::Sender<DriverEvent>,
    pub inspect: bool,
    pub inspect_assets: bool,
    pub capture_body_max: u64,
    pub retry: Option<RetryPolicy>,
    pub(crate) buffered_pending: AtomicU32,
    pub(crate) buffered_failed: AtomicU32,
    pub(crate) commands: mpsc::Sender<ConnCommand>,
}

impl EndpointHandle {
    pub fn record_buffered_status(&self, pending: u32, failed: u32) -> DriverEvent {
        self.buffered_pending.store(pending, Ordering::Release);
        self.buffered_failed.store(failed, Ordering::Release);
        DriverEvent::BufferedDelivery { pending, failed, delivered_delta: 0 }
    }

    pub fn record_buffered_result(&self, delivered: bool) -> DriverEvent {
        let previous = self.buffered_pending.fetch_sub(1, Ordering::AcqRel);
        let pending = previous.saturating_sub(1);
        if previous == 0 {
            self.buffered_pending.store(0, Ordering::Release);
        }
        let failed = if delivered {
            self.buffered_failed.load(Ordering::Acquire)
        } else {
            self.buffered_failed.fetch_add(1, Ordering::AcqRel).saturating_add(1)
        };
        DriverEvent::BufferedDelivery { pending, failed, delivered_delta: u64::from(delivered) }
    }
}

pub struct BindLease {
    pub bind: Uuid,
    pub reservation: Option<Uuid>,
    pub closed: watch::Receiver<bool>,
}
