//! Public TLS HTTP/1.1 edge and request tunneling into online sessions.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode, Version};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, body::Frame, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use wormhole_proto::frames::{HeaderField, HttpRequestHead, StreamHeader};

use crate::{
    certs::CertResolver,
    edge_auth::authorized,
    registry::{BindHandle, BindState, HostKey, HttpTunnelResponse, SessionCommand, UpgradeTunnel},
    session_streams::copy_bidirectional_idle,
    state::AppState,
};

pub use crate::edge_types::EdgeError;

const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_CHANNEL_CAPACITY: usize = 16;

type EdgeBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Bound public HTTPS listener.
pub struct HttpsEdge {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<AppState>,
}

impl HttpsEdge {
    /// Binds the public TCP listener using the shared wildcard resolver.
    pub async fn bind(
        address: SocketAddr,
        state: Arc<AppState>,
        resolver: Arc<CertResolver>,
    ) -> Result<Self, EdgeError> {
        let listener = TcpListener::bind(address).await?;
        Ok(Self::from_listener(listener, state, Self::tls_config(resolver)))
    }

    /// Builds an edge from a pre-bound listener so `:0` can feed URL allocation.
    pub fn from_listener(
        listener: TcpListener,
        state: Arc<AppState>,
        tls: rustls::ServerConfig,
    ) -> Self {
        Self { listener, acceptor: TlsAcceptor::from(Arc::new(tls)), state }
    }

    /// Builds the HTTP/1.1-only rustls configuration shared by startup wiring.
    pub fn tls_config(resolver: Arc<CertResolver>) -> rustls::ServerConfig {
        let mut tls =
            rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls
    }

    /// Returns the actual bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, EdgeError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts TLS connections until the listener task is cancelled.
    pub async fn run(&self) -> Result<(), EdgeError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let tls = match timeout(TLS_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, %peer, "TLS edge handshake rejected");
                        return;
                    }
                    Err(_) => return,
                };
                let Some(sni) = tls.get_ref().1.server_name().map(str::to_owned) else {
                    return;
                };
                let service = service_fn(move |request| {
                    handle_request(request, peer, sni.clone(), Arc::clone(&state))
                });
                let mut builder = http1::Builder::new();
                builder.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT);
                if let Err(error) =
                    builder.serve_connection(TokioIo::new(tls), service).with_upgrades().await
                {
                    tracing::debug!(%error, %peer, "HTTPS edge connection ended");
                }
            });
        }
    }
}

async fn handle_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    sni: String,
    state: Arc<AppState>,
) -> Result<Response<EdgeBody>, Infallible> {
    let response = route_request(request, peer, &sni, &state).await;
    Ok(response.unwrap_or_else(|error| {
        tracing::warn!(%error, %peer, %sni, "HTTPS edge request failed");
        static_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
    }))
}

async fn route_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    sni: &str,
    state: &AppState,
) -> Result<Response<EdgeBody>, EdgeError> {
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(hostname_from_authority);
    if !host.is_some_and(|host| host.eq_ignore_ascii_case(sni)) {
        return Ok(static_response(StatusCode::MISDIRECTED_REQUEST, "Misdirected Request"));
    }
    if state.registry.is_domain(sni) {
        return Ok(control_response(&request));
    }
    let Some(handle) = state.registry.get(&HostKey::Hostname(sni.to_owned())) else {
        return Ok(static_response(StatusCode::NOT_FOUND, "Not Found"));
    };
    if handle.state() != BindState::Online {
        return Ok(offline_response());
    }
    if !authorized(&request, &handle).await {
        return Ok(unauthorized_response());
    }
    proxy_request(request, peer, sni, handle).await
}

async fn proxy_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    sni: &str,
    handle: Arc<BindHandle>,
) -> Result<Response<EdgeBody>, EdgeError> {
    let session = handle.session().ok_or(EdgeError::Offline)?;
    let upgrade_requested = is_upgrade_request(&request);
    let public_upgrade = upgrade_requested.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let head = request_head(parts, peer, sni, upgrade_requested);
    let (body_tx, body_rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
    tokio::spawn(pump_request_body(body, body_tx));
    let (reply_tx, reply_rx) = oneshot::channel();
    session
        .send(SessionCommand::OpenHttp {
            header: StreamHeader::Http {
                bind: handle.bind_id,
                peer,
                request: head,
                buffered: None,
            },
            body: body_rx,
            upgrade: upgrade_requested,
            reply: reply_tx,
        })
        .await
        .map_err(|_| EdgeError::Offline)?;
    let tunneled = timeout(HEADER_TIMEOUT, reply_rx)
        .await
        .map_err(|_| EdgeError::HeaderTimeout)?
        .map_err(|_| EdgeError::Offline)?
        .map_err(EdgeError::Tunnel)?;
    response_from_tunnel(tunneled, public_upgrade)
}

async fn pump_request_body(mut body: Incoming, sender: mpsc::Sender<Result<Bytes, String>>) {
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data()
                    && sender.send(Ok(data)).await.is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _sent = sender.send(Err(error.to_string())).await;
                return;
            }
        }
    }
}

fn request_head(
    parts: http::request::Parts,
    peer: SocketAddr,
    sni: &str,
    upgrade: bool,
) -> HttpRequestHead {
    let mut headers = Vec::new();
    let connection_tokens = connection_tokens(
        parts
            .headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    for (name, value) in &parts.headers {
        let nominated = connection_tokens.iter().any(|token| token == name.as_str());
        if ((is_hop_header(name) || nominated) && !(upgrade && is_upgrade_header(name)))
            || is_forwarding_header(name)
        {
            continue;
        }
        headers.push(HeaderField {
            name: name.as_str().to_owned(),
            value_b64: STANDARD.encode(value.as_bytes()),
        });
    }
    append_header(&mut headers, "forwarded", &format!("for={};proto=https;host={sni}", peer.ip()));
    append_header(&mut headers, "x-forwarded-for", &peer.ip().to_string());
    append_header(&mut headers, "x-forwarded-proto", "https");
    HttpRequestHead {
        method: parts.method.as_str().to_owned(),
        uri: parts.uri.path_and_query().map_or("/", http::uri::PathAndQuery::as_str).to_owned(),
        version: version_string(parts.version).to_owned(),
        headers,
    }
}

fn response_from_tunnel(
    tunneled: HttpTunnelResponse,
    public_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<Response<EdgeBody>, EdgeError> {
    let status = tunneled.head.status;
    let connection_tokens = response_connection_tokens(&tunneled.head.headers);
    let mut builder = Response::builder().status(status);
    if let Some(headers) = builder.headers_mut() {
        for field in tunneled.head.headers {
            let name = HeaderName::from_bytes(field.name.as_bytes())?;
            let nominated = connection_tokens.iter().any(|token| token == name.as_str());
            if (is_hop_header(&name) || nominated) && !(status == 101 && is_upgrade_header(&name)) {
                continue;
            }
            let value = STANDARD.decode(field.value_b64)?;
            headers.append(name, HeaderValue::from_bytes(&value)?);
        }
    }
    if status == 101 {
        let tunnel = tunneled.upgrade.ok_or(EdgeError::MissingUpgrade)?;
        let public = public_upgrade.ok_or(EdgeError::MissingUpgrade)?;
        tokio::spawn(bridge_upgrade(public, tunnel));
        let body = Full::new(Bytes::new())
            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
            .boxed_unsync();
        return Ok(builder.body(body)?);
    }
    let stream = futures::stream::unfold(tunneled.body, |mut body| async move {
        body.recv().await.map(|result| {
            let frame = result.map(Frame::data).map_err(
                |error| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(error))
                },
            );
            (frame, body)
        })
    });
    Ok(builder.body(BodyExt::boxed_unsync(StreamBody::new(stream)))?)
}

async fn bridge_upgrade(public: hyper::upgrade::OnUpgrade, tunnel: UpgradeTunnel) {
    let Ok(public) = public.await else {
        return;
    };
    let UpgradeTunnel { recv, send, release } = tunnel;
    let public = TokioIo::new(public);
    let tunnel = tokio::io::join(recv, send);
    let _copied = copy_bidirectional_idle(public, tunnel).await;
    let _released = release.send(());
}

fn control_response(request: &Request<Incoming>) -> Response<EdgeBody> {
    if request.uri().path() == "/health" {
        static_response(StatusCode::OK, "ok")
    } else {
        static_response(StatusCode::NOT_FOUND, "Not Found")
    }
}

fn offline_response() -> Response<EdgeBody> {
    let mut response = static_response(StatusCode::SERVICE_UNAVAILABLE, "Tunnel Offline");
    response.headers_mut().insert(http::header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

fn unauthorized_response() -> Response<EdgeBody> {
    let mut response = static_response(StatusCode::UNAUTHORIZED, "Unauthorized");
    response.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"wormhole\""),
    );
    response
}

fn static_response(status: StatusCode, text: &'static str) -> Response<EdgeBody> {
    let body = Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
        .boxed_unsync();
    Response::builder().status(status).body(body).expect("static response is valid")
}

fn hostname_from_authority(authority: &str) -> Option<&str> {
    authority
        .split(':')
        .next()
        .filter(|host| !host.is_empty())
        .map(|host| host.strip_suffix('.').unwrap_or(host))
}

fn connection_tokens<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn response_connection_tokens(fields: &[HeaderField]) -> Vec<String> {
    let values = fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("connection"))
        .filter_map(|field| STANDARD.decode(&field.value_b64).ok())
        .filter_map(|value| String::from_utf8(value).ok())
        .collect::<Vec<_>>();
    connection_tokens(values.iter().map(String::as_str))
}

fn is_upgrade_request(request: &Request<Incoming>) -> bool {
    request.headers().contains_key(http::header::UPGRADE)
        && request
            .headers()
            .get(http::header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn is_upgrade_header(name: &HeaderName) -> bool {
    name == http::header::CONNECTION || name == http::header::UPGRADE
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

fn is_forwarding_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "forwarded" | "x-forwarded-for" | "x-forwarded-proto")
}

fn append_header(headers: &mut Vec<HeaderField>, name: &str, value: &str) {
    headers.push(HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) });
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

#[cfg(test)]
#[path = "edge_https_tests.rs"]
mod tests;
