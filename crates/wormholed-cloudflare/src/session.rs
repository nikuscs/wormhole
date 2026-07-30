use std::{cell::RefCell, rc::Rc};

use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
};
use worker::{Env, Request, Response, Result, SqlStorage, State, WebSocket};
use wormhole_proto::frames::StreamHeader;
use wormhole_proto::mux::{
    Direction, INITIAL_WINDOW, MAX_PAYLOAD, MAX_STREAMS, MuxControl, WsMessage,
};

use crate::{admin, api, edge_auth, storage, wire};

const MAX_BINDS: i64 = 32;
const MAX_RESPONSE_QUEUE: usize = 16;
const MAX_CONTROL_BUFFER: usize = 1024 * 1024 + 4;

#[path = "session_helpers.rs"]
mod helpers;
#[path = "session_response.rs"]
mod response;
#[path = "session_runtime.rs"]
mod runtime_state;
#[path = "session_socket.rs"]
mod socket;
#[path = "websocket_bridge.rs"]
mod websocket_bridge;
use helpers::{
    bind_error, close_protocol, control_domain, deny, invite_digest, parse_uuid, peer_address,
    protocol_error, relay_domain, secure_uuid, send_control, send_data, send_mux, valid_label,
};
pub use runtime_state::Runtime;
use runtime_state::{PendingHttp, SocketAttachment};
use socket::{connection_id, retire_connection, session_connection, socket_attachment, socket_for};

enum ForwardTarget {
    Ready { bind: Box<storage::BindRow>, connection: String, socket: WebSocket },
    Response(Response),
}

pub fn accept(state: &State) -> Result<Response> {
    let pair = worker::WebSocketPair::new()?;
    let connection = admin::random_token(18)?;
    let tag = format!("conn:{connection}");
    state.accept_websocket_with_tags(&pair.server, &[&tag]);
    pair.server.serialize_attachment(SocketAttachment::Unauthenticated)?;
    Response::from_websocket(pair.client)
}

pub fn message(
    state: &State,
    env: &Env,
    runtime: &RefCell<Runtime>,
    ws: WebSocket,
    bytes: Vec<u8>,
) -> Result<()> {
    let connection = connection_id(state, &ws)?;
    let message = WsMessage::decode(&bytes).map_err(protocol_error)?;
    if message.channel == 0 {
        handle_channel_zero(state, env, runtime, &ws, &connection, message.payload)
    } else {
        handle_data(runtime, &ws, &connection, message.channel, message.payload)
    }
}

fn handle_channel_zero(
    state: &State,
    env: &Env,
    runtime: &RefCell<Runtime>,
    ws: &WebSocket,
    connection: &str,
    payload: Vec<u8>,
) -> Result<()> {
    let Some((&kind, data)) = payload.split_first() else {
        return close_protocol(ws, "empty channel-zero message");
    };
    match kind {
        wire::CONTROL_DATA => {
            let frames = {
                let mut runtime = runtime.borrow_mut();
                let buffer = runtime.control.entry(connection.to_owned()).or_default();
                if buffer.len().saturating_add(data.len()) > MAX_CONTROL_BUFFER {
                    return close_protocol(ws, "control buffer exceeds limit");
                }
                buffer.extend_from_slice(data);
                wire::take_control_frames(buffer).map_err(protocol_error)?
            };
            for frame in frames {
                control::handle_control(state, env, runtime, ws, connection, frame)?;
            }
            Ok(())
        }
        wire::CONTROL_MUX => {
            let frame: MuxControl = serde_json::from_slice(data).map_err(protocol_error)?;
            handle_mux(runtime, ws, connection, frame)
        }
        _ => close_protocol(ws, "unknown channel-zero message"),
    }
}

fn handle_mux(
    runtime: &RefCell<Runtime>,
    ws: &WebSocket,
    connection: &str,
    frame: MuxControl,
) -> Result<()> {
    match frame {
        MuxControl::Ack { .. } | MuxControl::Fin { direction: Direction::Receive, .. } => Ok(()),
        MuxControl::Window { channel, bytes } => {
            if let Some(pending) =
                runtime.borrow_mut().pending.get_mut(&(connection.to_owned(), channel))
            {
                let _ignored = pending.credit.unbounded_send(bytes);
            }
            Ok(())
        }
        MuxControl::Fin { channel, direction: Direction::Send } => {
            finish_response(runtime, connection, channel);
            Ok(())
        }
        MuxControl::Reset { channel } => {
            reset_response(runtime, connection, channel, "client reset stream");
            Ok(())
        }
        MuxControl::Open { .. } => close_protocol(ws, "client-opened streams are unsupported"),
    }
}

fn handle_data(
    runtime: &RefCell<Runtime>,
    ws: &WebSocket,
    connection: &str,
    channel: u32,
    payload: Vec<u8>,
) -> Result<()> {
    let key = (connection.to_owned(), channel);
    let mut runtime = runtime.borrow_mut();
    let Some(pending) = runtime.pending.get_mut(&key) else {
        return send_mux(ws, &MuxControl::Reset { channel });
    };
    let consumed = payload.len();
    pending.buffer.extend_from_slice(&payload);
    if !pending.head_received
        && let Some(head) = wire::take_response_head(&mut pending.buffer).map_err(protocol_error)?
    {
        if head.status == 101 && !pending.upgrade {
            return reset_response_locked(
                &mut runtime,
                ws,
                key,
                "unexpected HTTP upgrade response",
            );
        }
        pending.head_received = true;
        if let Some(sender) = pending.head.take() {
            let _ignored = sender.send(Ok(head));
        }
    }
    let deferred = if pending.head_received && !pending.buffer.is_empty() {
        let body = std::mem::take(&mut pending.buffer);
        let length = body.len();
        if pending.body.try_send(Ok(body)).is_err() {
            return reset_response_locked(
                &mut runtime,
                ws,
                key,
                "response backpressure limit reached",
            );
        }
        length
    } else {
        0
    };
    drop(runtime);
    let immediate = consumed.saturating_sub(deferred);
    if immediate == 0 {
        return Ok(());
    }
    send_mux(ws, &MuxControl::Window { channel, bytes: immediate.try_into().unwrap_or(u32::MAX) })
}

pub async fn forward_http(
    state: &State,
    env: &Env,
    runtime: &Rc<RefCell<Runtime>>,
    sql: &SqlStorage,
    mut request: Request,
    hostname: &str,
) -> Result<Response> {
    let upgrade_header = request.headers().get("upgrade")?;
    let upgrade =
        upgrade_header.as_deref().is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if upgrade_header.is_some() && !upgrade {
        let response = api::error(
            501,
            "http_upgrade_unsupported",
            "only public WebSocket upgrades are supported on the Worker relay",
        );
        return early_response(&mut request, response).await;
    }
    let (bind, connection, ws) =
        match resolve_target(state, env, runtime, sql, &mut request, hostname).await? {
            ForwardTarget::Ready { bind, connection, socket } => (bind, connection, socket),
            ForwardTarget::Response(response) => return Ok(response),
        };
    let noindex = bind.persistent == 0;
    let Some(channel) = allocate_channel(runtime, &connection)? else {
        return early_response(
            &mut request,
            api::index_policy(
                api::error(503, "stream_limit_reached", "client session stream limit reached"),
                noindex,
            ),
        )
        .await;
    };
    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::channel(MAX_RESPONSE_QUEUE);
    let (credit_tx, credit_rx) = mpsc::unbounded();
    let mut credit_rx = Some(credit_rx);
    runtime.borrow_mut().pending.insert(
        (connection.clone(), channel),
        PendingHttp {
            head: Some(head_tx),
            body: body_tx,
            buffer: Vec::new(),
            head_received: false,
            credit: credit_tx,
            upgrade,
        },
    );
    let peer = request.headers().get("cf-connecting-ip")?.unwrap_or_else(|| "0.0.0.0".to_owned());
    let header = StreamHeader::Http {
        bind: parse_uuid(&bind.bind_id)?,
        peer: peer_address(&peer),
        request: wire::request_head(&request, &peer, hostname, upgrade),
        buffered: None,
    };
    send_mux(&ws, &MuxControl::Open { channel, header })?;
    let method = request.method().to_string();
    let request_body = if upgrade { None } else { request.stream().ok() };
    response::Context {
        runtime: Rc::clone(runtime),
        ws,
        connection,
        channel,
        body: body_rx,
        credits: Some(credit_rx.take().expect("credit receiver")),
        method,
        upgrade,
        noindex,
    }
    .finish(state, head_rx, request_body)
    .await
}

async fn resolve_target(
    state: &State,
    env: &Env,
    runtime: &RefCell<Runtime>,
    sql: &SqlStorage,
    request: &mut Request,
    hostname: &str,
) -> Result<ForwardTarget> {
    let cached = runtime.borrow().binds.get(hostname).cloned();
    let bind = match cached {
        Some(bind) => Some(bind),
        None => storage::bind_by_host(sql, hostname)?,
    };
    let Some(bind) = bind else {
        let response = api::error(404, "bind_not_found", "public hostname is not reserved");
        return early_response(request, response).await.map(ForwardTarget::Response);
    };
    runtime.borrow_mut().cache_bind(&bind);
    let noindex = bind.persistent == 0;
    if let Some(response) = edge_auth::authorize(request, env, &bind, hostname)? {
        return early_response(request, api::index_policy(Ok(response), noindex))
            .await
            .map(ForwardTarget::Response);
    }
    let Some(connection) = bind.connection_id.clone().filter(|_| bind.state == "online") else {
        let response = api::error(503, "bind_offline", "persistent bind is currently offline");
        return early_response(request, api::index_policy(response, noindex))
            .await
            .map(ForwardTarget::Response);
    };
    let Some(socket) = socket_for(state, &connection) else {
        mark_connection_offline(sql, &connection)?;
        runtime.borrow_mut().invalidate_connection(&connection);
        let response = api::error(503, "bind_offline", "client session is no longer connected");
        return early_response(request, api::index_policy(response, noindex))
            .await
            .map(ForwardTarget::Response);
    };
    Ok(ForwardTarget::Ready { bind: Box::new(bind), connection, socket })
}

async fn early_response(request: &mut Request, response: Result<Response>) -> Result<Response> {
    if request.inner().body().is_some() {
        let mut body = request.stream()?;
        while let Some(chunk) = body.next().await {
            let _discarded = chunk?;
        }
    }
    response
}

async fn pump_request(
    ws: WebSocket,
    channel: u32,
    mut body: Option<worker::ByteStream>,
    mut credits: mpsc::UnboundedReceiver<u32>,
) {
    let mut available = INITIAL_WINDOW as usize;
    if let Some(body) = body.as_mut() {
        while let Some(chunk) = body.next().await {
            let Ok(chunk) = chunk else { return };
            for part in chunk.chunks(MAX_PAYLOAD) {
                while available < part.len() {
                    let Some(credit) = credits.next().await else { return };
                    available = available.saturating_add(credit as usize);
                }
                if send_data(&ws, channel, part).is_err() {
                    return;
                }
                available -= part.len();
            }
        }
    }
    let _ignored = send_mux(&ws, &MuxControl::Fin { channel, direction: Direction::Send });
}

#[path = "session_control.rs"]
mod control;

pub fn closed(state: &State, runtime: &RefCell<Runtime>, ws: &WebSocket) -> Result<()> {
    let connection = connection_id(state, ws)?;
    let sql = state.storage().sql();
    mark_connection_offline(&sql, &connection)?;
    runtime.borrow_mut().invalidate_connection(&connection);
    sql.exec("DELETE FROM pending_auth WHERE connection_id=?", vec![connection.as_str().into()])?;
    let keys = runtime
        .borrow()
        .pending
        .keys()
        .filter(|(candidate, _)| candidate == &connection)
        .cloned()
        .collect::<Vec<_>>();
    for (_, channel) in keys {
        reset_response(runtime, &connection, channel, "client disconnected");
    }
    runtime.borrow_mut().control.remove(&connection);
    runtime.borrow_mut().next_channel.remove(&connection);
    Ok(())
}

fn mark_connection_offline(sql: &SqlStorage, connection: &str) -> Result<()> {
    sql.exec("DELETE FROM sessions WHERE connection_id=?", vec![connection.into()])?;
    sql.exec("DELETE FROM binds WHERE connection_id=? AND persistent=0", vec![connection.into()])?;
    sql.exec("UPDATE binds SET connection_id=NULL,state='offline' WHERE connection_id=? AND persistent=1", vec![connection.into()])?;
    Ok(())
}

fn allocate_channel(runtime: &RefCell<Runtime>, connection: &str) -> Result<Option<u32>> {
    let mut runtime = runtime.borrow_mut();
    if runtime.pending.keys().filter(|(candidate, _)| candidate == connection).count()
        >= MAX_STREAMS as usize
    {
        return Ok(None);
    }
    let next = runtime.next_channel.entry(connection.to_owned()).or_insert(2);
    let channel = *next;
    *next = next.checked_add(2).ok_or_else(|| protocol_error("mux channel space exhausted"))?;
    Ok(Some(channel))
}

fn finish_response(runtime: &RefCell<Runtime>, connection: &str, channel: u32) {
    if let Some(mut pending) =
        runtime.borrow_mut().pending.remove(&(connection.to_owned(), channel))
    {
        if let Some(sender) = pending.head.take() {
            let _ignored = sender.send(Err("response ended before headers".to_owned()));
        }
        pending.body.close_channel();
    }
}

fn reset_response(runtime: &RefCell<Runtime>, connection: &str, channel: u32, reason: &str) {
    if let Some(mut pending) =
        runtime.borrow_mut().pending.remove(&(connection.to_owned(), channel))
    {
        if let Some(sender) = pending.head.take() {
            let _ignored = sender.send(Err(reason.to_owned()));
        }
        let _ignored = pending.body.try_send(Err(worker::Error::RustError(reason.to_owned())));
        pending.body.close_channel();
    }
}

fn reset_response_locked(
    runtime: &mut Runtime,
    ws: &WebSocket,
    key: (String, u32),
    reason: &str,
) -> Result<()> {
    if let Some(mut pending) = runtime.pending.remove(&key) {
        if let Some(sender) = pending.head.take() {
            let _ignored = sender.send(Err(reason.to_owned()));
        }
        let _ignored = pending.body.try_send(Err(worker::Error::RustError(reason.to_owned())));
    }
    send_mux(ws, &MuxControl::Reset { channel: key.1 })
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
