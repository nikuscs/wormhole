//! Local HTTP and TCP delivery for server-opened Wormhole data streams.

use std::{convert::Infallible, error::Error, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use dashmap::DashMap;
use http::{HeaderName, HeaderValue, Method, Request, Version};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{body::Frame, client::conn::http1};
use hyper_util::rt::TokioIo;
use wormhole_proto::{
    codec::{read_stream_header, write_response_head},
    frames::{HeaderField, HttpRequestHead, HttpResponseHead, StreamHeader},
};

use crate::{error::DriverError, wormhole_conn::EndpointHandle};

type BoxError = Box<dyn Error + Send + Sync>;
type ClientBody = UnsyncBoxBody<Bytes, BoxError>;

struct AbortTask(tokio::task::JoinHandle<()>);

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
        tokio::spawn(accept_one_stream(send, recv, Arc::clone(&binds)));
    }
}

async fn accept_one_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    binds: Arc<DashMap<uuid::Uuid, Arc<EndpointHandle>>>,
) {
    let Ok(Ok(header)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), read_stream_header(&mut recv))
            .await
    else {
        let _reset = send.reset(0_u32.into());
        let _stopped = recv.stop(0_u32.into());
        return;
    };
    let bind = match &header {
        StreamHeader::Http { bind, .. } | StreamHeader::Tcp { bind, .. } => *bind,
    };
    let Some(handle) = binds.get(&bind).map(|handle| Arc::clone(&handle)) else {
        let _reset = send.reset(0_u32.into());
        let _stopped = recv.stop(0_u32.into());
        return;
    };
    dispatch_stream(send, recv, header, handle).await;
}

pub async fn dispatch_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    header: StreamHeader,
    handle: Arc<EndpointHandle>,
) {
    let Ok(permit) = Arc::clone(&handle.semaphore).try_acquire_owned() else {
        let _reset = send.reset(0_u32.into());
        let _stopped = recv.stop(0_u32.into());
        return;
    };
    if handle.inspect
        && let StreamHeader::Http { bind, request, .. } = &header
    {
        let _captured = handle
            .events
            .send(crate::driver::DriverEvent::Captured(Box::new(crate::model::CapturedRequest {
                bind_id: *bind,
                method: request.method.clone(),
                uri: request.uri.clone(),
                captured_at: jiff::Timestamp::now(),
            })))
            .await;
    }
    let delivery = async {
        let _permit = permit;
        match header {
            StreamHeader::Http { request, .. } => {
                deliver_http(send, recv, request, handle.target).await
            }
            StreamHeader::Tcp { .. } => deliver_tcp(send, recv, handle.target).await,
        }
    };
    tokio::select! {
        () = handle.stop.cancelled() => {}
        result = delivery => {
            if let Err(error) = result {
                let _sent = handle.events.send(crate::driver::DriverEvent::Log(
                    tracing::Level::WARN,
                    error.to_string(),
                )).await;
            }
        }
    }
}

async fn deliver_tcp(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
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
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    head: HttpRequestHead,
    target: crate::model::ResolvedTarget,
) -> Result<(), DriverError> {
    let upgrade = request_is_upgrade(&head);
    let (body, retained_recv) = request_body(recv, upgrade);
    let stream = tokio::net::TcpStream::connect(target.0)
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let _connection_task = AbortTask(tokio::spawn(async move {
        let _completed = connection.with_upgrades().await;
    }));
    let request = build_request(head, body, upgrade)?;
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let response_head = response_head(&response, upgrade);
    write_response_head(&mut send, &response_head)
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))?;
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
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|error| DriverError::Transport(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            send.write_all(&data)
                .await
                .map_err(|error| DriverError::Transport(error.to_string()))?;
        }
    }
    let _finished = send.finish();
    Ok(())
}

fn request_body(recv: quinn::RecvStream, upgrade: bool) -> (ClientBody, Option<quinn::RecvStream>) {
    if upgrade {
        let body = Full::new(Bytes::new())
            .map_err(|never: Infallible| -> BoxError { match never {} })
            .boxed_unsync();
        return (body, Some(recv));
    }
    let stream = futures::stream::unfold(recv, |mut recv| async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        match recv.read(&mut buffer).await {
            Ok(None) => None,
            Ok(Some(length)) => {
                Some((Ok(Frame::data(Bytes::copy_from_slice(&buffer[..length]))), recv))
            }
            Err(error) => Some((Err::<Frame<Bytes>, BoxError>(Box::new(error)), recv)),
        }
    });
    (BodyExt::boxed_unsync(StreamBody::new(stream)), None)
}

fn build_request(
    head: HttpRequestHead,
    body: ClientBody,
    preserve_upgrade: bool,
) -> Result<Request<ClientBody>, DriverError> {
    let mut builder = Request::builder()
        .method(Method::from_bytes(head.method.as_bytes()).map_err(protocol_error)?)
        .uri(head.uri)
        .version(parse_version(&head.version));
    let connection_tokens = connection_tokens(&head.headers);
    if let Some(headers) = builder.headers_mut() {
        for field in head.headers {
            let name = HeaderName::from_bytes(field.name.as_bytes()).map_err(protocol_error)?;
            if should_strip(&name, &connection_tokens, preserve_upgrade) {
                continue;
            }
            let value = STANDARD.decode(field.value_b64).map_err(protocol_error)?;
            headers.append(name, HeaderValue::from_bytes(&value).map_err(protocol_error)?);
        }
    }
    builder.body(body).map_err(protocol_error)
}

fn response_head(
    response: &hyper::Response<hyper::body::Incoming>,
    upgrade: bool,
) -> HttpResponseHead {
    let connection_tokens = response
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        if should_strip(name, &connection_tokens, upgrade) {
            continue;
        }
        headers.push(HeaderField {
            name: name.as_str().to_owned(),
            value_b64: STANDARD.encode(value.as_bytes()),
        });
    }
    HttpResponseHead {
        status: response.status().as_u16(),
        version: version_string(response.version()).to_owned(),
        headers,
    }
}

fn request_is_upgrade(head: &HttpRequestHead) -> bool {
    head.headers.iter().any(|field| field.name.eq_ignore_ascii_case("upgrade"))
}

fn connection_tokens(fields: &[HeaderField]) -> Vec<String> {
    fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("connection"))
        .filter_map(|field| STANDARD.decode(&field.value_b64).ok())
        .filter_map(|value| String::from_utf8(value).ok())
        .flat_map(|value| {
            value.split(',').map(str::trim).map(str::to_ascii_lowercase).collect::<Vec<_>>()
        })
        .collect()
}

fn should_strip(name: &HeaderName, connection_tokens: &[String], preserve_upgrade: bool) -> bool {
    let upgrade_header = name == http::header::CONNECTION || name == http::header::UPGRADE;
    (is_hop_header(name) || connection_tokens.iter().any(|token| token == name.as_str()))
        && !(preserve_upgrade && upgrade_header)
}

fn is_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
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

const fn version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

fn parse_version(version: &str) -> Version {
    match version {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2" => Version::HTTP_2,
        "HTTP/3" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

fn protocol_error(error: impl std::fmt::Display) -> DriverError {
    DriverError::Protocol(error.to_string())
}

#[cfg(test)]
#[path = "wormhole_stream_tests.rs"]
mod tests;
