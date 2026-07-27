use std::{path::PathBuf, time::Duration};

use tokio_util::sync::CancellationToken;

use super::{ManagedProcess, ProcessSpec, run_restarting, wait_healthy};

#[tokio::test]
async fn sleep_process_is_healthy_and_killed() {
    let process = ManagedProcess::spawn(&ProcessSpec::new(
        PathBuf::from("/bin/sleep"),
        vec!["30".to_owned()],
    ))
    .expect("spawn");
    let mut attempts = 0_u8;
    wait_healthy(Duration::from_secs(1), || {
        attempts = attempts.saturating_add(1);
        async move { attempts >= 2 }
    })
    .await
    .expect("healthy");
    process.terminate().await.expect("terminate");
}

#[tokio::test]
async fn crashed_process_restarts_until_cancelled() {
    let directory = tempfile::tempdir().expect("tempdir");
    let attempts = directory.path().join("attempts");
    let command = format!("echo attempt >> {}; exit 1", attempts.display());
    let spec = ProcessSpec::new("/bin/sh", vec!["-c".to_owned(), command]);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move { run_restarting(spec, stop, || async { false }).await }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let count =
            std::fs::read_to_string(&attempts).map_or(0, |contents| contents.lines().count());
        if count >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "process did not restart");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    stop.cancel();
    task.await.expect("join").expect("supervisor");
}
