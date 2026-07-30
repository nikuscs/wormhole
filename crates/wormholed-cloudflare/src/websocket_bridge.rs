//! Public Cloudflare WebSocket termination bridged to a raw local HTTP upgrade stream.

use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::Either, future::select};
use worker::{Response, Result, State, WebSocket, WebSocketPair, WebsocketEvent};
use wormhole_proto::{
    frames::HttpResponseHead,
    mux::{Direction, INITIAL_WINDOW, MAX_PAYLOAD, MuxControl},
};

use super::helpers::{protocol_error, send_data, send_mux};
use super::{Runtime, finish_response};
use crate::{websocket_wire, websocket_wire::Action};

pub(super) fn response(
    state: &State,
    upgrade: Upgrade,
    head: &HttpResponseHead,
    noindex: bool,
) -> Result<Response> {
    let pair = WebSocketPair::new()?;
    pair.server.accept()?;
    let headers = selected_protocol(head, noindex)?;
    state.wait_until(run(Bridge {
        public: pair.server,
        control: upgrade.control,
        connection: upgrade.connection,
        channel: upgrade.channel,
        body: upgrade.body,
        credits: upgrade.credits,
        runtime: upgrade.runtime,
    }));
    Ok(Response::from_websocket(pair.client)?.with_headers(headers))
}

pub(super) struct Upgrade {
    pub(super) control: WebSocket,
    pub(super) connection: String,
    pub(super) channel: u32,
    pub(super) body: mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>>,
    pub(super) credits: mpsc::UnboundedReceiver<u32>,
    pub(super) runtime: std::rc::Rc<std::cell::RefCell<Runtime>>,
}

struct Bridge {
    public: WebSocket,
    control: WebSocket,
    connection: String,
    channel: u32,
    body: mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>>,
    credits: mpsc::UnboundedReceiver<u32>,
    runtime: std::rc::Rc<std::cell::RefCell<Runtime>>,
}

async fn run(mut bridge: Bridge) {
    let result = bridge.run_inner().await;
    if result.is_err() {
        let _closed = bridge.public.close(Some(1011), Some("tunnel failed"));
        let _reset = send_mux(&bridge.control, &MuxControl::Reset { channel: bridge.channel });
    }
    finish_response(&bridge.runtime, &bridge.connection, bridge.channel);
}

impl Bridge {
    async fn run_inner(&mut self) -> Result<()> {
        let event_socket = self.public.clone();
        let mut events = event_socket.events()?;
        let mut decoder = websocket_wire::Decoder::default();
        let mut available = INITIAL_WINDOW as usize;
        loop {
            let event = events.next().fuse();
            let data = self.body.next().fuse();
            match select(event, data).await {
                Either::Left((event, _)) => {
                    if !self.public_event(event, &mut available).await? {
                        return Ok(());
                    }
                }
                Either::Right((data, _)) => {
                    if !self.local_data(data, &mut decoder, &mut available).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn public_event(
        &mut self,
        event: Option<Result<WebsocketEvent>>,
        available: &mut usize,
    ) -> Result<bool> {
        match event.transpose()? {
            Some(WebsocketEvent::Message(message)) => {
                let frame = if let Some(text) = message.text() {
                    websocket_wire::text(&text)
                } else if let Some(bytes) = message.bytes() {
                    websocket_wire::binary(&bytes)
                } else {
                    return Err(protocol_error("unsupported public WebSocket message"));
                }
                .map_err(protocol_error)?;
                self.send_tunnel(&frame, available).await?;
                Ok(true)
            }
            Some(WebsocketEvent::Close(close)) => {
                let frame =
                    websocket_wire::close(close.code(), &close.reason()).map_err(protocol_error)?;
                self.send_tunnel(&frame, available).await?;
                let _finished = send_mux(
                    &self.control,
                    &MuxControl::Fin { channel: self.channel, direction: Direction::Send },
                );
                Ok(false)
            }
            None => Ok(false),
        }
    }

    async fn local_data(
        &mut self,
        data: Option<std::result::Result<Vec<u8>, worker::Error>>,
        decoder: &mut websocket_wire::Decoder,
        available: &mut usize,
    ) -> Result<bool> {
        let Some(data) = data.transpose()? else {
            let _closed = self.public.close(Some(1001), Some("local WebSocket closed"));
            return Ok(false);
        };
        let actions = decoder.push(&data).map_err(protocol_error)?;
        send_mux(
            &self.control,
            &MuxControl::Window {
                channel: self.channel,
                bytes: data.len().try_into().unwrap_or(u32::MAX),
            },
        )?;
        for action in actions {
            if !self.apply_action(action, available).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn apply_action(&mut self, action: Action, available: &mut usize) -> Result<bool> {
        match action {
            Action::Text(text) => self.public.send_with_str(text)?,
            Action::Binary(bytes) => self.public.send_with_bytes(bytes)?,
            Action::Pong(payload) => {
                let frame = websocket_wire::pong(&payload).map_err(protocol_error)?;
                self.send_tunnel(&frame, available).await?;
            }
            Action::Close { code, reason } => {
                self.public.close(code, Some(reason))?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn send_tunnel(&mut self, bytes: &[u8], available: &mut usize) -> Result<()> {
        for chunk in bytes.chunks(MAX_PAYLOAD) {
            while *available < chunk.len() {
                let Some(credit) = self.credits.next().await else {
                    return Err(protocol_error("local WebSocket credit stream closed"));
                };
                *available = available.saturating_add(credit as usize);
            }
            send_data(&self.control, self.channel, chunk)?;
            *available -= chunk.len();
        }
        Ok(())
    }
}

fn selected_protocol(head: &HttpResponseHead, noindex: bool) -> Result<worker::Headers> {
    let headers = worker::Headers::new();
    if noindex {
        headers.set("x-robots-tag", crate::api::ROBOTS_TAG)?;
    }
    let Some(field) =
        head.headers.iter().find(|field| field.name.eq_ignore_ascii_case("sec-websocket-protocol"))
    else {
        return Ok(headers);
    };
    let value =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &field.value_b64)
            .map_err(protocol_error)?;
    let value = String::from_utf8(value).map_err(protocol_error)?;
    headers.set("sec-websocket-protocol", &value)?;
    Ok(headers)
}
