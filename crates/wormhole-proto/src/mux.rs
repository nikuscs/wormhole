//! Sans-I/O WebSocket fallback channel multiplexing.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::frames::StreamHeader;

pub const INITIAL_WINDOW: u32 = 256 * 1024;
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// Maximum concurrent data streams supported by one WebSocket mux session.
pub const MAX_STREAMS: u32 = 32;
/// Maximum payload for channel-zero mux envelopes, including `Open` stream headers.
pub const MAX_CONTROL_PAYLOAD: usize = MAX_PAYLOAD + 1024;
pub const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_QUEUED_MESSAGES_PER_CHANNEL: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum MuxControl {
    Open { channel: u32, header: StreamHeader },
    Ack { channel: u32 },
    Fin { channel: u32, direction: Direction },
    Reset { channel: u32 },
    Window { channel: u32, bytes: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMessage {
    pub channel: u32,
    pub payload: Vec<u8>,
}

impl WsMessage {
    pub fn encode(&self) -> Result<Vec<u8>, MuxError> {
        if self.payload.len() > payload_limit(self.channel) {
            return Err(MuxError::PayloadTooLarge);
        }
        let mut encoded = Vec::with_capacity(4 + self.payload.len());
        encoded.extend_from_slice(&self.channel.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, MuxError> {
        if encoded.len() < 4 {
            return Err(MuxError::PayloadTooLarge);
        }
        let channel = u32::from_be_bytes(encoded[..4].try_into().expect("four bytes"));
        if encoded.len() - 4 > payload_limit(channel) {
            return Err(MuxError::PayloadTooLarge);
        }
        Ok(Self { channel, payload: encoded[4..].to_vec() })
    }
}

const fn payload_limit(channel: u32) -> usize {
    if channel == 0 { MAX_CONTROL_PAYLOAD } else { MAX_PAYLOAD }
}

#[derive(Debug, Clone)]
struct Channel {
    send_window: u32,
    acknowledged: bool,
    send: SendState,
    receive_closed: bool,
    queue: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendState {
    Open,
    Closing,
    FinSent,
}

#[derive(Default)]
pub struct MuxState {
    channels: HashMap<u32, Channel>,
    order: VecDeque<u32>,
    queued_bytes: usize,
}

impl MuxState {
    pub fn open(&mut self, channel: u32) -> Result<(), MuxError> {
        if channel == 0 || self.channels.contains_key(&channel) {
            return Err(MuxError::InvalidState);
        }
        self.channels.insert(
            channel,
            Channel {
                send_window: INITIAL_WINDOW,
                acknowledged: false,
                send: SendState::Open,
                receive_closed: false,
                queue: VecDeque::new(),
            },
        );
        self.order.push_back(channel);
        Ok(())
    }

    pub fn acknowledge(&mut self, channel: u32) -> Result<(), MuxError> {
        self.channel_mut(channel)?.acknowledged = true;
        Ok(())
    }

    pub fn enqueue(&mut self, channel: u32, payload: Vec<u8>) -> Result<(), MuxError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(MuxError::PayloadTooLarge);
        }
        if self.queued_bytes.saturating_add(payload.len()) > MAX_QUEUED_BYTES {
            self.reset(channel);
            return Err(MuxError::QueueFull);
        }
        if self.channel_mut(channel)?.queue.len() >= MAX_QUEUED_MESSAGES_PER_CHANNEL {
            self.reset(channel);
            return Err(MuxError::QueueFull);
        }
        let length = payload.len();
        {
            let state = self.channel_mut(channel)?;
            if !state.acknowledged || state.send != SendState::Open {
                return Err(MuxError::InvalidState);
            }
            state.queue.push_back(payload);
        }
        self.queued_bytes += length;
        Ok(())
    }

    pub fn next_message(&mut self) -> Option<WsMessage> {
        for _ in 0..self.order.len() {
            let channel = self.order.pop_front()?;
            self.order.push_back(channel);
            let state = self.channels.get_mut(&channel)?;
            let Some(front) = state.queue.front() else {
                continue;
            };
            if front.len() > state.send_window as usize {
                continue;
            }
            let payload = state.queue.pop_front()?;
            state.send_window -= payload.len() as u32;
            self.queued_bytes -= payload.len();
            return Some(WsMessage { channel, payload });
        }
        None
    }

    pub fn take_ready_send_fin(&mut self) -> Option<u32> {
        let channel = self.order.iter().copied().find(|channel| {
            self.channels
                .get(channel)
                .is_some_and(|state| state.send == SendState::Closing && state.queue.is_empty())
        })?;
        self.channels.get_mut(&channel)?.send = SendState::FinSent;
        Some(channel)
    }

    pub fn add_window(&mut self, channel: u32, bytes: u32) -> Result<(), MuxError> {
        let state = self.channel_mut(channel)?;
        state.send_window = state.send_window.saturating_add(bytes);
        Ok(())
    }

    pub fn finish(&mut self, channel: u32, direction: Direction) -> Result<(), MuxError> {
        let state = self.channel_mut(channel)?;
        match direction {
            Direction::Send => state.send = SendState::Closing,
            Direction::Receive => state.receive_closed = true,
        }
        Ok(())
    }

    pub fn is_finished(&self, channel: u32) -> bool {
        self.channels
            .get(&channel)
            .is_some_and(|state| state.send == SendState::FinSent && state.receive_closed)
    }

    pub fn reset(&mut self, channel: u32) {
        if let Some(state) = self.channels.remove(&channel) {
            self.queued_bytes =
                self.queued_bytes.saturating_sub(state.queue.iter().map(Vec::len).sum::<usize>());
        }
        self.order.retain(|current| *current != channel);
    }

    pub fn close(&mut self) {
        self.channels.clear();
        self.order.clear();
        self.queued_bytes = 0;
    }

    fn channel_mut(&mut self, channel: u32) -> Result<&mut Channel, MuxError> {
        self.channels.get_mut(&channel).ok_or(MuxError::UnknownChannel)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MuxError {
    #[error("unknown mux channel")]
    UnknownChannel,
    #[error("invalid mux channel state")]
    InvalidState,
    #[error("mux payload exceeds its channel limit")]
    PayloadTooLarge,
    #[error("mux outbound queue exceeds its aggregate quota")]
    QueueFull,
}

#[cfg(test)]
#[path = "mux_tests.rs"]
mod tests;
