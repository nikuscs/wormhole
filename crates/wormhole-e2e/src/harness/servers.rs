use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    time::Duration,
};

use sha2::{Digest as _, Sha256};

use crate::helpers::to_string;

pub struct TcpEchoServer {
    listener: TcpListener,
    address: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl TcpEchoServer {
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(to_string)?;
        listener.set_nonblocking(true).map_err(to_string)?;
        let address = listener.local_addr().map_err(to_string)?;
        let worker = listener.try_clone().map_err(to_string)?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_worker = std::sync::Arc::clone(&stop);
        let task = std::thread::spawn(move || {
            while !stop_worker.load(std::sync::atomic::Ordering::Acquire) {
                match worker.accept() {
                    Ok((mut stream, _)) => {
                        let mut bytes = Vec::new();
                        let _read = stream.read_to_end(&mut bytes);
                        let _write = stream.write_all(&bytes);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { listener, address, stop, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }
}

impl Drop for TcpEchoServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _wake = std::net::TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
        let _ = &self.listener;
    }
}

pub struct EchoServer {
    listener: TcpListener,
    address: SocketAddr,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl EchoServer {
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(to_string)?;
        listener.set_nonblocking(true).map_err(to_string)?;
        let address = listener.local_addr().map_err(to_string)?;
        let worker = listener.try_clone().map_err(to_string)?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop_worker = std::sync::Arc::clone(&stop);
        let request_worker = std::sync::Arc::clone(&requests);
        let task = std::thread::spawn(move || serve_echo(worker, stop_worker, request_worker));
        Ok(Self { listener, address, requests, stop, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn request_count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _wake = std::net::TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
        let _ = &self.listener;
    }
}

fn serve_echo(
    listener: TcpListener,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let runtime = tokio::runtime::Runtime::new().expect("echo runtime");
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("echo listener");
        while !stop.load(std::sync::atomic::Ordering::Acquire) {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let requests = std::sync::Arc::clone(&requests);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request| {
                    handle_echo(request, std::sync::Arc::clone(&requests))
                });
                let _served = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

async fn handle_echo(
    request: hyper::Request<hyper::body::Incoming>,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    use http_body_util::BodyExt as _;
    requests.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_or_else(|_| bytes::Bytes::new(), http_body_util::Collected::to_bytes);
    let digest = Sha256::digest(&body);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("writing to String cannot fail");
    }
    let body = serde_json::json!({
        "method": parts.method.as_str(),
        "uri": parts.uri.to_string(),
        "request_hash": hash,
    })
    .to_string();
    Ok(hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(body))))
}
