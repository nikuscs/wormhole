use base64::{Engine as _, engine::general_purpose::STANDARD};
use wormhole_proto::{
    frames::{HeaderField, HttpRequestHead, HttpResponseHead},
    mux::{MAX_CONTROL_PAYLOAD, MuxControl, WsMessage},
};

pub const CONTROL_DATA: u8 = 0;
pub const CONTROL_MUX: u8 = 1;
pub const CONTROL_FRAME_LIMIT: usize = 1024 * 1024;
pub const DATA_HEAD_LIMIT: usize = 64 * 1024;

pub fn websocket_message(channel: u32, payload: Vec<u8>) -> Result<Vec<u8>, String> {
    WsMessage { channel, payload }.encode().map_err(|error| error.to_string())
}

pub fn control_frame(frame: &wormhole_proto::frames::ControlFrame) -> Result<Vec<u8>, String> {
    let encoded = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    if encoded.len() > CONTROL_FRAME_LIMIT {
        return Err("control frame exceeds limit".to_owned());
    }
    let mut payload = Vec::with_capacity(encoded.len() + 5);
    payload.push(CONTROL_DATA);
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    websocket_message(0, payload)
}

pub fn mux_control(frame: &MuxControl) -> Result<Vec<u8>, String> {
    let encoded = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_CONTROL_PAYLOAD {
        return Err("mux control frame exceeds limit".to_owned());
    }
    let mut payload = Vec::with_capacity(encoded.len() + 1);
    payload.push(CONTROL_MUX);
    payload.extend_from_slice(&encoded);
    websocket_message(0, payload)
}

pub fn take_control_frames(
    buffer: &mut Vec<u8>,
) -> Result<Vec<wormhole_proto::frames::ControlFrame>, String> {
    let mut frames = Vec::new();
    loop {
        if buffer.len() < 4 {
            return Ok(frames);
        }
        let length = u32::from_be_bytes(buffer[..4].try_into().expect("four bytes")) as usize;
        if length > CONTROL_FRAME_LIMIT {
            return Err("control frame exceeds limit".to_owned());
        }
        if buffer.len() < length + 4 {
            return Ok(frames);
        }
        let encoded = buffer[4..length + 4].to_vec();
        buffer.drain(..length + 4);
        frames.push(serde_json::from_slice(&encoded).map_err(|error| error.to_string())?);
    }
}

pub fn take_response_head(buffer: &mut Vec<u8>) -> Result<Option<HttpResponseHead>, String> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffer[..4].try_into().expect("four bytes")) as usize;
    if length > DATA_HEAD_LIMIT {
        return Err("response head exceeds limit".to_owned());
    }
    if buffer.len() < length + 4 {
        return Ok(None);
    }
    let head = serde_json::from_slice(&buffer[4..length + 4]).map_err(|error| error.to_string())?;
    buffer.drain(..length + 4);
    Ok(Some(head))
}

pub fn request_head(
    request: &worker::Request,
    peer: &str,
    hostname: &str,
    preserve_upgrade: bool,
) -> HttpRequestHead {
    let mut headers = request
        .headers()
        .entries()
        .filter(|(name, _)| should_forward_request_header(name, preserve_upgrade))
        .map(|(name, value)| HeaderField { name, value_b64: STANDARD.encode(value.as_bytes()) })
        .collect::<Vec<_>>();
    push_header(&mut headers, "forwarded", &format!("for={peer};proto=https;host={hostname}"));
    push_header(&mut headers, "x-forwarded-for", peer);
    push_header(&mut headers, "x-forwarded-host", hostname);
    push_header(&mut headers, "x-forwarded-proto", "https");
    HttpRequestHead {
        method: request.method().to_string(),
        uri: request.url().ok().map_or_else(
            || "/".to_owned(),
            |url| {
                url.query().map_or_else(
                    || url.path().to_owned(),
                    |query| format!("{}?{query}", url.path()),
                )
            },
        ),
        version: "HTTP/1.1".to_owned(),
        headers,
    }
}

pub const fn response_allows_body(method: &str, status: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD") && !matches!(status, 101 | 204 | 205 | 304)
}

pub fn response_headers(head: &HttpResponseHead, noindex: bool) -> Result<worker::Headers, String> {
    let headers = worker::Headers::new();
    for field in &head.headers {
        if is_hop_header(&field.name) {
            continue;
        }
        let value = STANDARD.decode(&field.value_b64).map_err(|error| error.to_string())?;
        let value = String::from_utf8(value)
            .map_err(|_| "non-UTF-8 response header unsupported".to_owned())?;
        headers.append(&field.name, &value).map_err(|error| error.to_string())?;
    }
    if noindex {
        headers.set("x-robots-tag", crate::api::ROBOTS_TAG).map_err(|error| error.to_string())?;
    }
    Ok(headers)
}

fn push_header(headers: &mut Vec<HeaderField>, name: &str, value: &str) {
    headers.push(HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) });
}

fn should_forward_request_header(name: &str, preserve_upgrade: bool) -> bool {
    (!is_hop_header(name) || (preserve_upgrade && is_upgrade_header(name)))
        && !is_forwarding_header(name)
        && !(preserve_upgrade && name.eq_ignore_ascii_case("sec-websocket-extensions"))
}

const fn is_upgrade_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("upgrade")
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_forwarding_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "forwarded" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto"
    )
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
