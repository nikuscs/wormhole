use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use jiff::Timestamp;

use super::{detect_child_port, reserve_port, wait_for_listener};

const CHILD_PORT_ENV: &str = "WORMHOLE_PORT_TEST_CHILD_PORT";

#[test]
fn reservation_holds_port_until_child_spawn() {
    let (port, reservation) = reserve_port(4000..=4999).expect("reservation");
    assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err());
    drop(reservation);
    assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[tokio::test]
async fn allocated_listener_is_reachable_and_detected_for_process() {
    // Keep this process-handoff test outside the application allocator's shared 4000-4999 range.
    let (port, reservation) = reserve_port(50_000..=59_999).expect("reservation");
    let started = Timestamp::now();
    drop(reservation);
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "ports::tests::child_listener_helper", "--nocapture"])
        .env(CHILD_PORT_ENV, port.to_string())
        .spawn()
        .expect("listener child");
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    wait_for_listener(addr, Duration::from_secs(2)).await.expect("listener reachable");
    let detected = detect_child_port(child.id(), started);
    child.kill().expect("stop listener child");
    let _status = child.wait().expect("wait listener child");

    assert_eq!(detected, Some(port));
}

#[test]
fn child_listener_helper() {
    let Ok(port) = std::env::var(CHILD_PORT_ENV) else {
        return;
    };
    let port = port.parse::<u16>().expect("child port");
    let _listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("child listener");
    std::thread::sleep(Duration::from_secs(10));
}
