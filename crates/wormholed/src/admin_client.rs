//! Minimal HTTP/1.1 client for the local administration Unix socket.

use std::path::Path;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::UnixStream;

pub struct AdminResponse {
    pub status: StatusCode,
    pub body: Bytes,
}

pub async fn request<T: Serialize + ?Sized>(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<&T>,
) -> Result<AdminResponse, AdminClientError> {
    let stream = UnixStream::connect(socket).await.map_err(AdminClientError::Connect)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _completed = connection.await;
    });
    let encoded = body.map(serde_json::to_vec).transpose()?.unwrap_or_default();
    let mut builder = Request::builder().method(method).uri(path).header("host", "localhost");
    if !encoded.is_empty() {
        builder = builder.header(http::header::CONTENT_TYPE, "application/json");
    }
    let response = sender.send_request(builder.body(Full::new(Bytes::from(encoded)))?).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok(AdminResponse { status, body })
}

pub fn encoded_path(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _written = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    #[error("connecting to administration socket: {0}")]
    Connect(std::io::Error),
    #[error(transparent)]
    Http(#[from] hyper::Error),
    #[error(transparent)]
    Build(#[from] http::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
