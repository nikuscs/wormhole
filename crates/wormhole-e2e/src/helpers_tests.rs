use std::{
    process::Command,
    time::{Duration, Instant},
};

use super::helpers::{attempt_deadline, curl_max_time, output_until};

#[test]
fn observation_attempts_do_not_consume_the_global_deadline() {
    let now = Instant::now();
    let global = now + Duration::from_secs(10);
    let attempt = attempt_deadline(global);
    assert!(attempt < global);
    assert!(attempt <= now + Duration::from_millis(1_100));
}

#[test]
fn curl_timeout_is_shorter_than_remaining_deadline() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let timeout = curl_max_time(deadline).expect("curl timeout");
    let timeout = timeout.parse::<f64>().expect("numeric timeout");
    assert!(timeout > 0.0);
    assert!(timeout < 2.0);
}

#[test]
fn process_output_is_terminated_at_deadline() {
    let deadline = Instant::now() + Duration::from_millis(50);
    let mut command = Command::new("/bin/sleep");
    command.arg("5");
    let started = Instant::now();
    let error = output_until(&mut command, deadline, "sleep command").expect_err("timeout");
    assert!(error.contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(2));
}
