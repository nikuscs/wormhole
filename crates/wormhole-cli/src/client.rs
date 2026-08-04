//! Typed local API client with daemon auto-spawn.

use std::{path::PathBuf, process::Stdio, time::Duration};

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};
use tokio::net::UnixStream;
use wormhole_core::{ActiveEndpoint, ifaces::IfaceAlias, model::DoctorCheck};

use crate::{
    daemon::read_token,
    local_api::{
        ClosedResponse, CreateServiceRequest, RemoteAddRequest, RemoteView, ServiceView,
        StatusResponse,
    },
    runtime::RuntimePaths,
};

pub struct DaemonClient {
    paths: RuntimePaths,
    token: String,
}

impl DaemonClient {
    pub async fn ensure(config: Option<&PathBuf>) -> Result<Self, ClientError> {
        let paths = RuntimePaths::discover()?;
        if Self::connect(&paths).await.is_err() {
            spawn(config)?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                if Self::connect(&paths).await.is_ok() {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ClientError::Unavailable);
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
        let token = read_token(&paths)?;
        let client = Self { paths, token };
        client.status().await?;
        Ok(client)
    }

    pub async fn status(&self) -> Result<StatusResponse, ClientError> {
        self.json(Method::GET, "/v1/status", Option::<&()>::None).await
    }

    pub async fn services(&self, watch: bool) -> Result<Vec<ServiceView>, ClientError> {
        self.json(
            Method::GET,
            if watch { "/v1/services?watch=1" } else { "/v1/services" },
            Option::<&()>::None,
        )
        .await
    }

    pub async fn remotes(&self) -> Result<Vec<RemoteView>, ClientError> {
        self.json(Method::GET, "/v1/remotes", Option::<&()>::None).await
    }

    pub async fn add_remote(&self, request: &RemoteAddRequest) -> Result<RemoteView, ClientError> {
        self.json(Method::POST, "/v1/remotes", Some(request)).await
    }

    pub async fn remove_remote(&self, name: &str) -> Result<ClosedResponse, ClientError> {
        self.json(
            Method::DELETE,
            &format!("/v1/remotes/{}", encode_path_segment(name)),
            Option::<&()>::None,
        )
        .await
    }

    pub async fn endpoints(&self) -> Result<Vec<ActiveEndpoint>, ClientError> {
        self.json(Method::GET, "/v1/endpoints", Option::<&()>::None).await
    }

    pub async fn create(
        &self,
        request: &CreateServiceRequest,
    ) -> Result<Vec<ActiveEndpoint>, ClientError> {
        self.json(Method::POST, "/v1/services", Some(request)).await
    }

    /// Creates a service, superseding an identically named one that is still registered.
    ///
    /// An attached command owns its service for as long as it runs, so restarting it must not be
    /// blocked by a predecessor that never deregistered, such as one orphaned by a signal its
    /// parent absorbed. Reservations are kept so the public URL survives the handover.
    pub async fn create_replacing(
        &self,
        request: &CreateServiceRequest,
    ) -> Result<Vec<ActiveEndpoint>, ClientError> {
        match self.create(request).await {
            Err(ClientError::Api { status, message })
                if status == StatusCode::CONFLICT && message.contains("service already exists") =>
            {
                self.delete_service(&request.service.name, request.project_id.as_deref(), false)
                    .await?;
                self.create(request).await
            }
            result => result,
        }
    }

    pub async fn delete_service(
        &self,
        name: &str,
        project_id: Option<&str>,
        forget: bool,
    ) -> Result<ClosedResponse, ClientError> {
        self.json(
            Method::DELETE,
            &format!(
                "/v1/services/{}?forget={}&project_id={}",
                encode_path_segment(name),
                u8::from(forget),
                project_id.unwrap_or_default()
            ),
            Option::<&()>::None,
        )
        .await
    }

    pub async fn delete_endpoint(
        &self,
        id: uuid::Uuid,
        forget: bool,
    ) -> Result<ClosedResponse, ClientError> {
        self.json(
            Method::DELETE,
            &format!("/v1/endpoints/{id}?forget={}", u8::from(forget)),
            Option::<&()>::None,
        )
        .await
    }

    pub async fn interfaces(&self) -> Result<Vec<IfaceAlias>, ClientError> {
        self.json(Method::GET, "/v1/interfaces", Option::<&()>::None).await
    }

    pub async fn doctor(&self) -> Result<Vec<DoctorCheck>, ClientError> {
        self.json(Method::GET, "/v1/doctor", Option::<&()>::None).await
    }

    pub async fn shutdown(&self) -> Result<ClosedResponse, ClientError> {
        self.json(Method::POST, "/v1/shutdown", Option::<&()>::None).await
    }

    pub async fn reload(&self) -> Result<ClosedResponse, ClientError> {
        self.json(Method::POST, "/v1/reload", Option::<&()>::None).await
    }

    pub async fn captures(
        &self,
        endpoint: Option<&str>,
        since: Option<jiff::Timestamp>,
    ) -> Result<Vec<wormhole_core::CapturedRequest>, ClientError> {
        let mut query = Vec::new();
        if let Some(endpoint) = endpoint {
            query.push(format!("endpoint={endpoint}"));
        }
        if let Some(since) = since {
            query.push(format!("since={since}"));
        }
        let path = if query.is_empty() {
            "/v1/requests".to_owned()
        } else {
            format!("/v1/requests?{}", query.join("&"))
        };
        self.json(Method::GET, &path, Option::<&()>::None).await
    }

    pub async fn capture(
        &self,
        id: uuid::Uuid,
    ) -> Result<wormhole_core::CapturedRequest, ClientError> {
        self.json(Method::GET, &format!("/v1/requests/{id}"), Option::<&()>::None).await
    }

    pub async fn replay(
        &self,
        id: uuid::Uuid,
    ) -> Result<crate::future_api::ReplayResponse, ClientError> {
        self.json(Method::POST, &format!("/v1/requests/{id}/replay"), Option::<&()>::None).await
    }

    pub async fn clear_captures(&self) -> Result<ClosedResponse, ClientError> {
        self.json(Method::DELETE, "/v1/requests", Option::<&()>::None).await
    }

    pub async fn share(
        &self,
        request: &crate::share_api::ShareRequest,
    ) -> Result<crate::share_api::ShareResponse, ClientError> {
        self.json(Method::POST, "/v1/share", Some(request)).await
    }

    async fn connect(paths: &RuntimePaths) -> Result<(), std::io::Error> {
        UnixStream::connect(&paths.socket).await.map(|_| ())
    }

    async fn json<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, ClientError> {
        let payload = body.map(serde_json::to_vec).transpose()?;
        let response = self.request(method, path, payload).await?;
        if !response.status.is_success() {
            let message = serde_json::from_slice::<crate::local_api::ApiErrorBody>(&response.body)
                .map_or_else(
                    |_| String::from_utf8_lossy(&response.body).into_owned(),
                    |error| error.error.message,
                );
            return Err(ClientError::Api { status: response.status, message });
        }
        serde_json::from_slice(&response.body).map_err(Into::into)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RawResponse, ClientError> {
        let stream = UnixStream::connect(&self.paths.socket).await?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "local API connection ended");
            }
        });
        let payload = body.unwrap_or_default();
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "localhost")
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        if !payload.is_empty() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let response = sender.send_request(request.body(Full::new(Bytes::from(payload)))?).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes().to_vec();
        Ok(RawResponse { status, body })
    }
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

struct RawResponse {
    status: StatusCode,
    body: Vec<u8>,
}

fn spawn(config: Option<&PathBuf>) -> Result<(), ClientError> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    if let Some(path) = config {
        command.arg("--config").arg(path);
    }
    command
        .args(["daemon", "run", "--detach"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("daemon did not become reachable within 3 seconds")]
    Unavailable,
    #[error("local API returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Daemon(#[from] crate::daemon::DaemonError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
