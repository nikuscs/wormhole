use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sha2::{Digest as _, Sha256};
use worker::{Env, Result, WebSocket};
use wormhole_proto::frames::{ControlFrame, DenyReason};
use wormhole_proto::mux::MuxControl;

use crate::wire;

pub(super) fn send_control(ws: &WebSocket, frame: &ControlFrame) -> Result<()> {
    ws.send_with_bytes(wire::control_frame(frame).map_err(protocol_error)?)
}

pub(super) fn send_mux(ws: &WebSocket, frame: &MuxControl) -> Result<()> {
    ws.send_with_bytes(wire::mux_control(frame).map_err(protocol_error)?)
}

pub(super) fn send_data(ws: &WebSocket, channel: u32, data: &[u8]) -> Result<()> {
    ws.send_with_bytes(wire::websocket_message(channel, data.to_vec()).map_err(protocol_error)?)
}

pub(super) fn deny(ws: &WebSocket, reason: DenyReason) -> Result<()> {
    send_control(ws, &ControlFrame::Denied { reason })?;
    ws.close(Some(1008), Some("authentication denied"))
}

pub(super) fn bind_error(ws: &WebSocket, request: uuid::Uuid, reason: &str) -> Result<()> {
    send_control(ws, &ControlFrame::BindError { request, reason: reason.to_owned() })
}

pub(super) fn close_protocol(ws: &WebSocket, reason: &str) -> Result<()> {
    ws.close(Some(1002), Some(reason))
}

pub(super) fn protocol_error(error: impl ToString) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

pub(super) fn relay_domain(env: &Env) -> Result<String> {
    configured_domain(env, "RELAY_DOMAIN")
}

pub(super) fn control_domain(env: &Env) -> Result<String> {
    configured_domain(env, "CONTROL_DOMAIN")
}

fn configured_domain(env: &Env, name: &str) -> Result<String> {
    Ok(env.var(name)?.to_string().trim_end_matches('.').to_ascii_lowercase())
}

pub(super) fn parse_uuid(value: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(value).map_err(protocol_error)
}

pub(super) fn secure_uuid() -> Result<uuid::Uuid> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(protocol_error)?;
    Ok(uuid::Uuid::from_bytes(bytes))
}

pub(super) fn peer_address(value: &str) -> SocketAddr {
    value.parse::<IpAddr>().map_or_else(
        |_| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        |ip| SocketAddr::new(ip, 0),
    )
}

pub(super) fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub(super) fn invite_digest(token: &str) -> Option<(String, String)> {
    let encoded = token.strip_prefix("whi_")?;
    let (id, secret) = encoded.split_once('_')?;
    if id.len() != 12 || secret.len() != 43 {
        return None;
    }
    Some((
        id.to_owned(),
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(secret.as_bytes()),
        ),
    ))
}
