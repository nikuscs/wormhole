//! Local HTTP and TCP delivery for server-opened Wormhole data streams.
use std::{convert::Infallible, error::Error, sync::Arc};

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{body::Frame, client::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
};
use wormhole_proto::{
    codec::{read_stream_header, write_response_head},
    frames::{HttpRequestHead, HttpResponseHead, StreamHeader},
};

use crate::{
    capture::CaptureContext,
    error::DriverError,
    wormhole_conn::{ConnCommand, EndpointHandle},
    wormhole_http::{build_request, request_is_upgrade, response_head},
    wormhole_request_body::{
        PublicReadError, request_body, request_body_with_prefix, retain_request_body,
    },
    wormhole_retry_response::{forward_spooled_response, spool_retry_response},
};

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;
pub type ClientBody = UnsyncBoxBody<Bytes, BoxError>;

struct CaptureSink<'a> {
    capture: Option<CaptureContext>,
    events: &'a mpsc::Sender<crate::driver::DriverEvent>,
}

struct HttpDelivery<'a> {
    target: crate::model::ResolvedTarget,
    retry: Option<&'a crate::model::RetryPolicy>,
    buffered: bool,
    capture: CaptureSink<'a>,
}

pub struct AbortTask(tokio::task::JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn accept_streams(
    connection: quinn::Connection,
    binds: Arc<DashMap<uuid::Uuid, Arc<EndpointHandle>>>,
) {
    while let Ok((send, recv)) = connection.accept_bi().await {
        tokio::spawn(accept_one_stream(Box::new(send), Box::new(recv), Arc::clone(&binds)));
    }
}

pub async fn accept_mux_streams(
    mut incoming: mpsc::Receiver<tokio::io::DuplexStream>,
    binds: Arc<DashMap<uuid::Uuid, Arc<EndpointHandle>>>,
) {
    while let Some(stream) = incoming.recv().await {
        let (recv, send) = tokio::io::split(stream);
        tokio::spawn(accept_one_stream(Box::new(send), Box::new(recv), Arc::clone(&binds)));
    }
}

async fn accept_one_stream(
    mut send: BoxWrite,
    mut recv: BoxRead,
    binds: Arc<DashMap<uuid::Uuid, Arc<EndpointHandle>>>,
) {
    let Ok(Ok(header)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), read_stream_header(&mut recv))
            .await
    else {
        let _closed = send.shutdown().await;
        return;
    };
    let bind = match &header {
        StreamHeader::Http { bind, .. } | StreamHeader::Tcp { bind, .. } => *bind,
    };
    let Some(handle) = binds.get(&bind).map(|handle| Arc::clone(&handle)) else {
        let _closed = send.shutdown().await;
        return;
    };
    dispatch_stream(send, recv, header, handle).await;
}

pub async fn dispatch_stream(
    mut send: BoxWrite,
    recv: BoxRead,
    header: StreamHeader,
    handle: Arc<EndpointHandle>,
) {
    let Ok(permit) = Arc::clone(&handle.semaphore).try_acquire_owned() else {
        let _closed = send.shutdown().await;
        return;
    };
    let capture = if handle.inspect {
        match &header {
            StreamHeader::Http { bind, request, .. } => CaptureContext::eligible(
                *bind,
                request,
                handle.inspect_assets,
                handle.capture_body_max,
            ),
            StreamHeader::Tcp { .. } => None,
        }
    } else {
        None
    };
    let buffered = match &header {
        StreamHeader::Http { bind, buffered: Some(seq), .. } => Some((*bind, *seq)),
        _ => None,
    };
    let retry = handle.retry.clone();
    let delivery = async {
        let _permit = permit;
        match header {
            StreamHeader::Http { request, .. } => {
                deliver_http(
                    send,
                    recv,
                    request,
                    HttpDelivery {
                        target: handle.target,
                        retry: retry.as_ref(),
                        buffered: buffered.is_some(),
                        capture: CaptureSink { capture: capture.clone(), events: &handle.events },
                    },
                )
                .await
            }
            StreamHeader::Tcp { .. } => deliver_tcp(send, recv, handle.target).await.map(|()| 0),
        }
    };
    let result = tokio::select! {
        () = handle.stop.cancelled() => Err(DriverError::Cancelled),
        result = delivery => result,
    };
    if let Some(capture) = capture {
        let delivery = match &result {
            Ok(0) => "ok".to_owned(),
            Ok(retries) => format!("retried({retries})"),
            Err(_) => "failed".to_owned(),
        };
        if let Some(captured) = capture.finish_once(&delivery) {
            let _captured =
                handle.events.send(crate::driver::DriverEvent::Captured(Box::new(captured))).await;
        }
    }
    if let Some((bind, seq)) = buffered {
        handle_buffered_result(&handle, bind, seq, result).await;
    } else if let Err(error) = result {
        let _sent = handle
            .events
            .send(crate::driver::DriverEvent::Log(tracing::Level::WARN, error.to_string()))
            .await;
    }
}

async fn handle_buffered_result(
    handle: &EndpointHandle,
    bind: uuid::Uuid,
    seq: u64,
    result: Result<u32, DriverError>,
) {
    let message = match result {
        Ok(_) => Some(Ok(())),
        Err(DriverError::LocalDelivery(error) | DriverError::LocalConnect(error)) => {
            let _sent = handle
                .events
                .send(crate::driver::DriverEvent::Log(
                    tracing::Level::WARN,
                    format!("buffered webhook {seq} delivery exhausted: {error}"),
                ))
                .await;
            Some(Err(error))
        }
        Err(error) => {
            let _sent = handle
                .events
                .send(crate::driver::DriverEvent::Log(
                    tracing::Level::WARN,
                    format!("buffered webhook {seq} transport interrupted: {error}"),
                ))
                .await;
            None
        }
    };
    if let Some(result) = message {
        let _sent = handle.commands.send(ConnCommand::BufferedResult { bind, seq, result }).await;
    }
}

async fn deliver_tcp(
    send: BoxWrite,
    recv: BoxRead,
    target: crate::model::ResolvedTarget,
) -> Result<(), DriverError> {
    let public = tokio::io::join(recv, send);
    let local = tokio::net::TcpStream::connect(target.0)
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let mut public = public;
    let mut local = local;
    tokio::io::copy_bidirectional(&mut public, &mut local)
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    Ok(())
}

async fn deliver_http(
    send: BoxWrite,
    recv: BoxRead,
    head: HttpRequestHead,
    delivery: HttpDelivery<'_>,
) -> Result<u32, DriverError> {
    let upgrade = request_is_upgrade(&head);
    if let Some(policy) = delivery.retry
        && !upgrade
    {
        let (prefix, recv, complete) =
            retain_request_body(recv, policy.max_body_bytes, delivery.capture.capture.clone())
                .await?;
        if complete {
            return deliver_http_with_retry(
                send,
                head,
                delivery.target,
                delivery.capture,
                policy,
                prefix,
                delivery.buffered,
            )
            .await;
        }
        let body = request_body_with_prefix(
            prefix,
            recv.expect("incomplete body stream"),
            delivery.capture.capture.clone(),
        );
        return deliver_http_once(send, head, delivery.target, delivery.capture, body, None, false)
            .await
            .map(|()| 0);
    }
    let (body, retained_recv) = request_body(recv, upgrade, delivery.capture.capture.clone());
    deliver_http_once(send, head, delivery.target, delivery.capture, body, retained_recv, upgrade)
        .await
        .map(|()| 0)
}

async fn deliver_http_once(
    send: BoxWrite,
    head: HttpRequestHead,
    target: crate::model::ResolvedTarget,
    capture: CaptureSink<'_>,
    body: ClientBody,
    retained_recv: Option<BoxRead>,
    upgrade: bool,
) -> Result<(), DriverError> {
    let (response, connection_task) = http_attempt(head, target, body, upgrade).await?;
    forward_response(send, response, connection_task, capture, retained_recv, upgrade, None).await
}

async fn http_attempt(
    head: HttpRequestHead,
    target: crate::model::ResolvedTarget,
    body: ClientBody,
    upgrade: bool,
) -> Result<(hyper::Response<hyper::body::Incoming>, AbortTask), DriverError> {
    let stream = tokio::net::TcpStream::connect(target.0)
        .await
        .map_err(|error| DriverError::LocalConnect(error.to_string()))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| DriverError::LocalConnect(error.to_string()))?;
    let connection_task = AbortTask(tokio::spawn(async move {
        let _completed = connection.with_upgrades().await;
    }));
    let request = build_request(head, body, upgrade)?;
    let response = sender.send_request(request).await.map_err(classify_send_error)?;
    Ok((response, connection_task))
}

fn classify_send_error(error: hyper::Error) -> DriverError {
    let mut source = error.source();
    while let Some(current) = source {
        if current.downcast_ref::<PublicReadError>().is_some() {
            return DriverError::Transport(error.to_string());
        }
        source = current.source();
    }
    DriverError::LocalDelivery(error.to_string())
}

async fn forward_response(
    mut send: BoxWrite,
    mut response: hyper::Response<hyper::body::Incoming>,
    _connection_task: AbortTask,
    capture: CaptureSink<'_>,
    retained_recv: Option<BoxRead>,
    upgrade: bool,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), DriverError> {
    let head = response_head(&response, upgrade);
    if let Some(capture) = &capture.capture {
        capture.response_head(&head);
    }
    write_response_head(&mut send, &head)
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))?;
    if response.status() == http::StatusCode::SWITCHING_PROTOCOLS
        && let Some(captured) =
            capture.capture.as_ref().and_then(|capture| capture.finish_once("ok"))
    {
        let _sent =
            capture.events.send(crate::driver::DriverEvent::Captured(Box::new(captured))).await;
    }
    if response.status() == http::StatusCode::SWITCHING_PROTOCOLS && upgrade {
        let public_recv = retained_recv.ok_or_else(|| {
            DriverError::Protocol("upgrade request lost its public receive stream".to_owned())
        })?;
        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let mut local = TokioIo::new(upgraded);
        let mut public = tokio::io::join(public_recv, send);
        tokio::io::copy_bidirectional(&mut local, &mut public)
            .await
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        return Ok(());
    }
    while let Some(frame) = next_response_frame(&mut response, deadline).await? {
        if let Ok(data) = frame.into_data() {
            if let Some(capture) = &capture.capture {
                capture.response_bytes(&data);
            }
            send.write_all(&data)
                .await
                .map_err(|error| DriverError::Transport(error.to_string()))?;
        }
    }
    send.shutdown().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    Ok(())
}

async fn deliver_http_with_retry(
    mut send: BoxWrite,
    head: HttpRequestHead,
    target: crate::model::ResolvedTarget,
    capture: CaptureSink<'_>,
    policy: &crate::model::RetryPolicy,
    body: Vec<u8>,
    buffered: bool,
) -> Result<u32, DriverError> {
    let deadline = crate::retry::deadline(policy);
    let attempts = policy.max_attempts.max(1);
    for attempt in 0..attempts {
        let request_body = Full::new(Bytes::copy_from_slice(&body))
            .map_err(|never: Infallible| -> BoxError { match never {} })
            .boxed_unsync();
        let result = tokio::time::timeout_at(
            deadline,
            http_attempt(head.clone(), target, request_body, false),
        )
        .await;
        match result {
            Ok(Ok((response, connection_task))) => {
                let retry_status = policy.retry_5xx && response.status().is_server_error();
                if !retry_status {
                    forward_response(
                        send,
                        response,
                        connection_task,
                        capture,
                        None,
                        false,
                        buffered.then_some(deadline),
                    )
                    .await?;
                    return Ok(attempt);
                }
                match spool_retry_response(response, connection_task, deadline).await {
                    Ok(response) if attempt + 1 == attempts => {
                        forward_spooled_response(&mut send, response, capture.capture.as_ref())
                            .await?;
                        send.shutdown()
                            .await
                            .map_err(|error| DriverError::Transport(error.to_string()))?;
                        if buffered {
                            return Err(DriverError::LocalDelivery(
                                "buffered local delivery returned repeated 5xx".to_owned(),
                            ));
                        }
                        return Ok(attempt);
                    }
                    Err(error) if attempt + 1 == attempts => {
                        write_gateway_timeout(&mut send).await?;
                        return Err(error);
                    }
                    Ok(_) | Err(_) => {}
                }
            }
            Ok(Err(DriverError::LocalConnect(_)))
                if policy.retry_connect && attempt + 1 < attempts => {}
            Ok(Err(error)) => {
                write_gateway_timeout(&mut send).await?;
                return Err(error);
            }
            Err(_) => {
                write_gateway_timeout(&mut send).await?;
                return Err(DriverError::LocalDelivery(
                    "local delivery deadline exceeded".to_owned(),
                ));
            }
        }
        if attempt + 1 < attempts {
            let delay = crate::retry::retry_delay(policy, attempt);
            if tokio::time::Instant::now() + delay >= deadline {
                break;
            }
            tokio::time::sleep(delay).await;
        }
    }
    write_gateway_timeout(&mut send).await?;
    Err(DriverError::LocalDelivery("local delivery retries exhausted".to_owned()))
}

async fn next_response_frame(
    response: &mut hyper::Response<hyper::body::Incoming>,
    deadline: Option<tokio::time::Instant>,
) -> Result<Option<Frame<Bytes>>, DriverError> {
    let next = response.body_mut().frame();
    let frame = if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, next).await.map_err(|_| {
            DriverError::LocalDelivery("local delivery deadline exceeded".to_owned())
        })?
    } else {
        next.await
    };
    frame.transpose().map_err(|error| DriverError::LocalDelivery(error.to_string()))
}

async fn write_gateway_timeout(send: &mut BoxWrite) -> Result<(), DriverError> {
    let head =
        HttpResponseHead { status: 504, version: "HTTP/1.1".to_owned(), headers: Vec::new() };
    write_response_head(send, &head)
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))?;
    send.write_all(b"Gateway Timeout")
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    send.shutdown().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
#[path = "wormhole_stream_tests.rs"]
mod tests;
