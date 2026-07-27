//! Local delivery retry timing and classification.

use rand::RngExt as _;

use crate::model::RetryPolicy;

pub fn retry_delay(policy: &RetryPolicy, retry_index: u32) -> std::time::Duration {
    let exponent = retry_index.min(31);
    let cap = policy.initial_delay_ms.saturating_mul(1_u64 << exponent).min(policy.max_delay_ms);
    std::time::Duration::from_millis(rand::rng().random_range(0..=cap))
}

pub const fn retry_status(policy: &RetryPolicy, status: u16) -> bool {
    policy.retry_5xx && status >= 500 && status <= 599
}

pub fn deadline(policy: &RetryPolicy) -> tokio::time::Instant {
    tokio::time::Instant::now() + std::time::Duration::from_millis(policy.total_deadline_ms)
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
