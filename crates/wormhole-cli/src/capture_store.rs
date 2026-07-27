//! Daemon-owned bounded memory-only inspection ring.

use std::collections::VecDeque;

use uuid::Uuid;
use wormhole_core::CapturedRequest;

const ENDPOINT_LIMIT: usize = 20;
const GLOBAL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
pub struct CaptureStore {
    records: VecDeque<CapturedRequest>,
    bytes: usize,
}

impl CaptureStore {
    pub fn insert(&mut self, endpoint: Uuid, mut capture: CapturedRequest) {
        capture.endpoint_id = Some(endpoint);
        while self.records.iter().filter(|record| record.endpoint_id == Some(endpoint)).count()
            >= ENDPOINT_LIMIT
        {
            if let Some(index) =
                self.records.iter().position(|record| record.endpoint_id == Some(endpoint))
            {
                self.remove(index);
            }
        }
        let size = capture_size(&capture);
        while self.bytes.saturating_add(size) > GLOBAL_BYTES && !self.records.is_empty() {
            self.remove(0);
        }
        if size <= GLOBAL_BYTES {
            self.bytes = self.bytes.saturating_add(size);
            self.records.push_back(capture);
        }
    }

    pub fn list(
        &self,
        endpoint: Option<Uuid>,
        since: Option<jiff::Timestamp>,
        limit: usize,
    ) -> Vec<CapturedRequest> {
        self.records
            .iter()
            .rev()
            .filter(|record| endpoint.is_none_or(|id| record.endpoint_id == Some(id)))
            .filter(|record| since.is_none_or(|time| record.captured_at > time))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get(&self, id: Uuid) -> Option<CapturedRequest> {
        self.records.iter().find(|record| record.id == id).cloned()
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }

    fn remove(&mut self, index: usize) {
        if let Some(record) = self.records.remove(index) {
            self.bytes = self.bytes.saturating_sub(capture_size(&record));
        }
    }
}

fn capture_size(record: &CapturedRequest) -> usize {
    std::mem::size_of::<CapturedRequest>()
        + record.method.capacity()
        + record.uri.capacity()
        + record.delivery.capacity()
        + record.body.capacity()
        + record.response_body_prefix.capacity()
        + headers_size(&record.headers)
        + headers_size(&record.response_headers)
}

fn headers_size(headers: &[wormhole_core::model::CapturedHeader]) -> usize {
    std::mem::size_of_val(headers)
        + headers
            .iter()
            .map(|header| header.name.capacity() + header.value_b64.capacity())
            .sum::<usize>()
}
