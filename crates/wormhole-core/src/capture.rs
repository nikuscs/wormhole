//! Bounded, redacted in-memory HTTP exchange capture.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use parking_lot::Mutex;
use uuid::Uuid;
use wormhole_proto::frames::{HeaderField, HttpRequestHead, HttpResponseHead};

use crate::model::{CapturedHeader, CapturedRequest};

const OVERSIZED_PREFIX: usize = 128 * 1024;
const RESPONSE_MAX: usize = 128 * 1024;

#[derive(Clone)]
pub struct CaptureContext(Arc<Mutex<CaptureState>>);

struct CaptureState {
    captured: CapturedRequest,
    started: std::time::Instant,
    request_max: usize,
    request_complete: bool,
    finished: bool,
}

impl CaptureContext {
    pub fn eligible(
        bind: Uuid,
        request: &HttpRequestHead,
        include_assets: bool,
        request_max: u64,
    ) -> Option<Self> {
        if !include_assets && is_static_asset(request) {
            return None;
        }
        Some(Self(Arc::new(Mutex::new(CaptureState {
            captured: CapturedRequest {
                id: Uuid::now_v7(),
                endpoint_id: None,
                bind_id: bind,
                method: request.method.clone(),
                uri: request.uri.clone(),
                headers: redact(&request.headers),
                body: Vec::new(),
                body_truncated: false,
                response_status: None,
                response_headers: Vec::new(),
                response_body_prefix: Vec::new(),
                response_body_truncated: false,
                duration_ms: 0,
                delivery: "ok".to_owned(),
                captured_at: jiff::Timestamp::now(),
            },
            started: std::time::Instant::now(),
            request_max: usize::try_from(request_max).unwrap_or(usize::MAX),
            request_complete: false,
            finished: false,
        }))))
    }

    pub fn request_bytes(&self, bytes: &[u8]) {
        let mut state = self.0.lock();
        if state.captured.body_truncated {
            let remaining = OVERSIZED_PREFIX.saturating_sub(state.captured.body.len());
            state.captured.body.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
            return;
        }
        let exceeds = state.captured.body.len().saturating_add(bytes.len()) > state.request_max;
        state.captured.body.extend_from_slice(bytes);
        if exceeds {
            state.captured.body.truncate(OVERSIZED_PREFIX);
            state.captured.body_truncated = true;
        }
    }

    pub fn complete_request(&self) {
        self.0.lock().request_complete = true;
    }

    pub fn response_head(&self, response: &HttpResponseHead) {
        let mut state = self.0.lock();
        state.captured.response_status = Some(response.status);
        state.captured.response_headers = redact(&response.headers);
    }

    pub fn response_bytes(&self, bytes: &[u8]) {
        let mut state = self.0.lock();
        {
            let captured = &mut state.captured;
            append_bounded(
                &mut captured.response_body_prefix,
                &mut captured.response_body_truncated,
                bytes,
                RESPONSE_MAX,
            );
        }
        drop(state);
    }

    pub fn finish_once(&self, delivery: &str) -> Option<CapturedRequest> {
        let mut state = self.0.lock();
        if state.finished {
            return None;
        }
        state.finished = true;
        if !state.request_complete {
            state.captured.body_truncated = true;
        }
        state.captured.duration_ms =
            state.started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        delivery.clone_into(&mut state.captured.delivery);
        Some(state.captured.clone())
    }
}

fn append_bounded(target: &mut Vec<u8>, truncated: &mut bool, bytes: &[u8], limit: usize) {
    let remaining = limit.saturating_sub(target.len());
    target.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    *truncated |= bytes.len() > remaining;
}

fn redact(headers: &[HeaderField]) -> Vec<CapturedHeader> {
    headers
        .iter()
        .map(|header| CapturedHeader {
            name: header.name.clone(),
            value_b64: if is_secret(&header.name) {
                STANDARD.encode("«redacted»")
            } else {
                header.value_b64.clone()
            },
        })
        .collect()
}

fn is_secret(name: &str) -> bool {
    ["authorization", "cookie", "set-cookie", "x-api-key"]
        .iter()
        .any(|secret| name.eq_ignore_ascii_case(secret))
}

fn is_static_asset(request: &HttpRequestHead) -> bool {
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return false;
    }
    let path = request.uri.split('?').next().unwrap_or(&request.uri).to_ascii_lowercase();
    [
        ".js", ".map", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".otf",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
        || path.ends_with("/favicon.ico")
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
