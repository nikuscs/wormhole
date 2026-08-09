//! Portless local-hostname driver backed by the shared Host router.

use std::sync::Arc;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use tokio::sync::{OnceCell, mpsc};
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::DriverError,
    local_ca::{LocalCertResolver, LocalCertificateAuthority},
    local_router::{LocalRouter, RouteRegistration, shared},
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

/// Local HTTP and HTTPS Host-routing driver.
pub struct LocalDriver {
    router: Arc<LocalRouter>,
    http_port: u16,
    https_port: u16,
    ca_directory: Option<Utf8PathBuf>,
    resolver: OnceCell<Arc<LocalCertResolver>>,
}

impl LocalDriver {
    /// Creates the production driver using the process-wide router.
    pub fn new(clear_port: u16, tls_port: u16, ca_directory: Option<Utf8PathBuf>) -> Self {
        Self {
            router: shared(),
            http_port: clear_port,
            https_port: tls_port,
            ca_directory,
            resolver: OnceCell::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn isolated(clear_port: u16, tls_port: u16, ca_directory: Utf8PathBuf) -> Self {
        Self {
            router: Arc::new(LocalRouter::new()),
            http_port: clear_port,
            https_port: tls_port,
            ca_directory: Some(ca_directory),
            resolver: OnceCell::new(),
        }
    }

    async fn resolver(&self) -> Result<Arc<LocalCertResolver>, DriverError> {
        self.resolver
            .get_or_try_init(|| async {
                let directory = self.ca_directory.as_deref().ok_or_else(|| {
                    DriverError::Transport(
                        "Wormhole configuration directory is unavailable".to_owned(),
                    )
                })?;
                let authority = LocalCertificateAuthority::load_or_create(directory)
                    .map_err(|error| DriverError::Transport(error.to_string()))?;
                Ok(Arc::new(LocalCertResolver::new(Arc::new(authority))))
            })
            .await
            .map(Arc::clone)
    }
}

#[async_trait]
impl TunnelDriver for LocalDriver {
    fn name(&self) -> &'static str {
        "local"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::default()
    }

    fn validate(&self, spec: &EndpointSpec) -> Result<(), DriverError> {
        if spec.proto != ServiceProto::Http {
            return Err(DriverError::Capability("local driver is HTTP-only".to_owned()));
        }
        if spec.qualifier.is_some() || spec.remote.is_some() || spec.domain.is_some() {
            return Err(DriverError::Capability(
                "local endpoints do not accept qualifiers, remotes, or domains".to_owned(),
            ));
        }
        if spec.public_port.is_some() {
            return Err(DriverError::Capability(
                "local endpoints use defaults.local_http_port, not public_port".to_owned(),
            ));
        }
        if spec.persist == Persistence::Persistent {
            return Err(DriverError::Capability("local endpoints cannot be persistent".to_owned()));
        }
        if !spec.host.as_deref().is_some_and(valid_hostname) {
            return Err(DriverError::Capability(
                "local endpoints require a valid lowercase hostname".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check(&self) -> DriverHealth {
        DriverHealth::Healthy
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        self.validate(&spec)?;
        let hostname = spec.host.as_deref().expect("validated local hostname");
        let http = self.router.register(self.http_port, hostname, target.0).await?;
        let resolver = match self.resolver().await {
            Ok(resolver) => resolver,
            Err(error) => {
                http.close().await;
                return Err(error);
            }
        };
        let https =
            match self.router.register_https(self.https_port, hostname, target.0, resolver).await {
                Ok(registration) => registration,
                Err(error) => {
                    http.close().await;
                    return Err(error);
                }
            };
        let urls = endpoint_urls(hostname, &http, &https).await?;
        if events.send(DriverEvent::Ready { urls, bind_id: None, reservation: None }).await.is_err()
        {
            close_routes(http, https).await;
            return Err(DriverError::Cancelled);
        }
        stop.cancelled().await;
        close_routes(http, https).await;
        Ok(())
    }
}

async fn endpoint_urls(
    hostname: &str,
    http: &RouteRegistration,
    https: &RouteRegistration,
) -> Result<Vec<String>, DriverError> {
    let clear_port = listener_port(http).await?;
    let tls_port = listener_port(https).await?;
    Ok(vec![
        local_url("https", hostname, tls_port, 443),
        local_url("http", hostname, clear_port, 80),
    ])
}

async fn listener_port(registration: &RouteRegistration) -> Result<u16, DriverError> {
    registration
        .listener_address()
        .await
        .map(|address| address.port())
        .ok_or_else(|| DriverError::Transport("local listener disappeared".to_owned()))
}

async fn close_routes(http: RouteRegistration, https: RouteRegistration) {
    https.close().await;
    http.close().await;
}

fn local_url(scheme: &str, hostname: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        format!("{scheme}://{hostname}")
    } else {
        format!("{scheme}://{hostname}:{port}")
    }
}

fn valid_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
