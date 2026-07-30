//! RFC 6455 framing between Cloudflare's message API and a tunneled raw upgrade stream.

const FIN: u8 = 0x80;
const MASK: u8 = 0x80;
const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Text(String),
    Binary(Vec<u8>),
    Pong(Vec<u8>),
    Close { code: Option<u16>, reason: String },
}

#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    fragmented: Option<(u8, Vec<u8>)>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Action>, String> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_MESSAGE + 14 {
            return Err("WebSocket receive buffer exceeds limit".to_owned());
        }
        self.buffer.extend_from_slice(bytes);
        let mut actions = Vec::new();
        while let Some(frame) = take_frame(&mut self.buffer)? {
            self.handle_frame(frame, &mut actions)?;
        }
        Ok(actions)
    }

    fn handle_frame(&mut self, frame: Frame, actions: &mut Vec<Action>) -> Result<(), String> {
        if frame.control {
            return Self::handle_control(frame, actions);
        }
        match frame.opcode {
            0 => self.continue_message(frame, actions),
            1 | 2 if self.fragmented.is_none() => {
                if frame.fin {
                    actions.push(message_action(frame.opcode, frame.payload)?);
                } else {
                    self.fragmented = Some((frame.opcode, frame.payload));
                }
                Ok(())
            }
            1 | 2 => Err("nested fragmented WebSocket message".to_owned()),
            _ => Err("unsupported WebSocket opcode".to_owned()),
        }
    }

    fn continue_message(&mut self, frame: Frame, actions: &mut Vec<Action>) -> Result<(), String> {
        let Some((_opcode, payload)) = &mut self.fragmented else {
            return Err("unexpected WebSocket continuation".to_owned());
        };
        if payload.len().saturating_add(frame.payload.len()) > MAX_MESSAGE {
            return Err("fragmented WebSocket message exceeds limit".to_owned());
        }
        payload.extend_from_slice(&frame.payload);
        if frame.fin {
            let (opcode, payload) = self.fragmented.take().expect("fragment exists");
            actions.push(message_action(opcode, payload)?);
        }
        Ok(())
    }

    fn handle_control(frame: Frame, actions: &mut Vec<Action>) -> Result<(), String> {
        if !frame.fin || frame.payload.len() > 125 {
            return Err("invalid fragmented WebSocket control frame".to_owned());
        }
        match frame.opcode {
            8 => actions.push(close_action(frame.payload)?),
            9 => actions.push(Action::Pong(frame.payload)),
            10 => {}
            _ => return Err("unsupported WebSocket control opcode".to_owned()),
        }
        Ok(())
    }
}

struct Frame {
    fin: bool,
    control: bool,
    opcode: u8,
    payload: Vec<u8>,
}

fn take_frame(buffer: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let first = buffer[0];
    let second = buffer[1];
    if first & 0x70 != 0 {
        return Err("WebSocket extensions are unsupported".to_owned());
    }
    if second & MASK != 0 {
        return Err("local WebSocket server sent a masked frame".to_owned());
    }
    let short = second & 0x7f;
    if (short == 126 && buffer.len() < 4) || (short == 127 && buffer.len() < 10) {
        return Ok(None);
    }
    let (length, header) = payload_length(buffer, short)?;
    if length > MAX_MESSAGE {
        return Err("WebSocket frame exceeds limit".to_owned());
    }
    let total = header.checked_add(length).ok_or_else(|| "WebSocket frame overflow".to_owned())?;
    if buffer.len() < total {
        return Ok(None);
    }
    let payload = buffer[header..total].to_vec();
    buffer.drain(..total);
    let opcode = first & 0x0f;
    Ok(Some(Frame { fin: first & FIN != 0, control: opcode >= 8, opcode, payload }))
}

fn payload_length(buffer: &[u8], short: u8) -> Result<(usize, usize), String> {
    match short {
        0..=125 => Ok((short as usize, 2)),
        126 => Ok((u16::from_be_bytes([buffer[2], buffer[3]]) as usize, 4)),
        127 => {
            let length = u64::from_be_bytes(buffer[2..10].try_into().expect("eight bytes"));
            let length =
                usize::try_from(length).map_err(|_| "WebSocket frame is too large".to_owned())?;
            Ok((length, 10))
        }
        _ => unreachable!(),
    }
}

fn message_action(opcode: u8, payload: Vec<u8>) -> Result<Action, String> {
    if opcode == 1 {
        String::from_utf8(payload)
            .map(Action::Text)
            .map_err(|_| "WebSocket text message is not UTF-8".to_owned())
    } else {
        Ok(Action::Binary(payload))
    }
}

fn close_action(payload: Vec<u8>) -> Result<Action, String> {
    if payload.is_empty() {
        return Ok(Action::Close { code: None, reason: String::new() });
    }
    if payload.len() == 1 {
        return Err("WebSocket close frame has an invalid code".to_owned());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = String::from_utf8(payload[2..].to_vec())
        .map_err(|_| "WebSocket close reason is not UTF-8".to_owned())?;
    Ok(Action::Close { code: Some(code), reason })
}

pub fn text(value: &str) -> Result<Vec<u8>, String> {
    encode(1, value.as_bytes())
}

pub fn binary(value: &[u8]) -> Result<Vec<u8>, String> {
    encode(2, value)
}

pub fn pong(value: &[u8]) -> Result<Vec<u8>, String> {
    encode(10, value)
}

pub fn close(code: u16, reason: &str) -> Result<Vec<u8>, String> {
    let mut payload = Vec::with_capacity(reason.len() + 2);
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    if payload.len() > 125 {
        return Err("WebSocket close reason exceeds limit".to_owned());
    }
    encode(8, &payload)
}

fn encode(opcode: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_MESSAGE {
        return Err("WebSocket message exceeds limit".to_owned());
    }
    if opcode >= 8 && payload.len() > 125 {
        return Err("WebSocket control message exceeds limit".to_owned());
    }
    let mut mask = [0_u8; 4];
    getrandom::fill(&mut mask).map_err(|error| error.to_string())?;
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(FIN | opcode);
    match payload.len() {
        0..=125 => frame.push(MASK | payload.len() as u8),
        126..=65_535 => {
            frame.push(MASK | 0x7e);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(MASK | 0x7f);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(index, byte)| byte ^ mask[index % 4]));
    Ok(frame)
}

#[cfg(test)]
#[path = "websocket_wire_tests.rs"]
mod tests;
