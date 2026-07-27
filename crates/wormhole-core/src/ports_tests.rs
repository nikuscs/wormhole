use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use jiff::Timestamp;

use super::{alloc_port, detect_child_port, reserve_port, wait_for_listener};

#[test]
fn reservation_holds_port_until_child_spawn() {
    let (port, reservation) = reserve_port(4000..=4999).expect("reservation");
    assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err());
    drop(reservation);
    assert!(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[tokio::test]
async fn allocated_listener_is_reachable_and_detected_for_process() {
    let port = alloc_port(4000..=4999).expect("free port");
    let listener =
        tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.expect("listener");
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    wait_for_listener(addr, Duration::from_secs(2)).await.expect("listener reachable");
    let detected = detect_child_port(std::process::id(), Timestamp::now());

    assert_eq!(detected, Some(listener.local_addr().expect("address").port()));
}
