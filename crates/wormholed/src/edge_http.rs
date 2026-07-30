//! Plain HTTP listener that permanently redirects to the public HTTPS authority.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

/// Bound HTTP redirect listener.
pub struct HttpRedirectEdge {
    listener: TcpListener,
    https_port: u16,
    domains: Arc<Vec<String>>,
}

impl HttpRedirectEdge {
    /// Binds the redirect listener using the externally visible HTTPS port.
    pub async fn bind(
        address: SocketAddr,
        https_port: u16,
        domains: Vec<String>,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            https_port,
            domains: Arc::new(domains),
        })
    }

    /// Returns the actual bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Accepts HTTP/1.1 connections until cancelled.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let https_port = self.https_port;
            let domains = Arc::clone(&self.domains);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    std::future::ready(Ok::<_, Infallible>(redirect(request, https_port, &domains)))
                });
                let mut builder = http1::Builder::new();
                builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                if let Err(error) = builder.serve_connection(TokioIo::new(stream), service).await {
                    tracing::debug!(%error, %peer, "HTTP redirect connection ended");
                }
            });
        }
    }
}

fn redirect(
    request: Request<Incoming>,
    https_port: u16,
    domains: &[String],
) -> Response<Full<Bytes>> {
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|authority| authority.split(':').next());
    let Some(host) = host.filter(|host| allowed_host(host, domains)) else {
        let mut response = Response::new(Full::new(Bytes::new()));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    };
    let path = request.uri().path_and_query().map_or("/", http::uri::PathAndQuery::as_str);
    let location = redirect_location(host, path, https_port);
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    if let Ok(location) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(http::header::LOCATION, location);
    }
    response
}

fn allowed_host(host: &str, domains: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    domains.iter().any(|domain| {
        host == *domain
            || host.strip_suffix(domain).is_some_and(|prefix| {
                prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
            })
    })
}

fn redirect_location(host: &str, path: &str, https_port: u16) -> String {
    let authority =
        if https_port == 443 { host.to_owned() } else { format!("{host}:{https_port}") };
    format!("https://{authority}{path}")
}

#[cfg(test)]
#[path = "edge_http_tests.rs"]
mod tests;
