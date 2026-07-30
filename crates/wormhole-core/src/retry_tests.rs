use crate::model::RetryPolicy;

fn policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 5,
        initial_delay_ms: 500,
        max_delay_ms: 3000,
        retry_connect: true,
        retry_5xx: true,
        max_body_bytes: 1024,
        total_deadline_ms: 60_000,
    }
}

#[test]
fn delay_is_capped_and_status_is_opt_in() {
    let policy = policy();
    assert!(super::retry_delay(&policy, 20).as_millis() <= 3000);
    assert!(super::retry_status(&policy, 503));
    assert!(!super::retry_status(&policy, 404));
    let mut disabled = policy;
    disabled.retry_5xx = false;
    assert!(!super::retry_status(&disabled, 503));
}
