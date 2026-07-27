//! HTTP and TCP data-stream tasks spawned by authenticated session actors.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tracing::Instrument;
use wormhole_proto::{
    codec::{read_response_head, write_stream_header},
    frames::{HttpResponseHead, StreamHeader},
};

use crate::{
    registry::{HttpTunnelResponse, UpgradeTunnel},
    state::AppState,
};

const DATA_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

pub fn spawn_http_stream(
    connection: quinn::Connection,
    state: Arc<AppState>,
    permit: tokio::sync::OwnedSemaphorePermit,
    header: StreamHeader,
    request_body: mpsc::Receiver<Result<bytes::Bytes, String>>,
    upgrade: bool,
    reply: oneshot::Sender<Result<HttpTunnelResponse, String>>,
) {
    let bind = stream_bind(&header);
    let span = tracing::info_span!("stream", %bind, protocol = "http");
    let stream = state.track_stream();
    tokio::spawn(
        async move {
            let _stream = stream;
            let _permit = permit;
            match open_http_stream(connection, header, request_body, upgrade).await {
                Ok(OpenedHttp::Body { response, sender, mut recv }) => {
                    if reply.send(Ok(response)).is_err() {
                        let _stopped = recv.stop(0_u32.into());
                        return;
                    }
                    stream_response_body(recv, sender).await;
                }
                Ok(OpenedHttp::Upgrade { response, released }) => {
                    if reply.send(Ok(response)).is_ok() {
                        let _released = released.await;
                    }
                }
                Err(error) => {
                    let _sent = reply.send(Err(error));
                }
            }
        }
        .instrument(span),
    );
}

pub fn spawn_tcp_stream(
    connection: quinn::Connection,
    state: Arc<AppState>,
    permit: tokio::sync::OwnedSemaphorePermit,
    header: StreamHeader,
    public_stream: tokio::net::TcpStream,
) {
    let bind = stream_bind(&header);
    let span = tracing::info_span!("stream", %bind, protocol = "tcp");
    let stream = state.track_stream();
    tokio::spawn(
        async move {
            let _stream = stream;
            let _permit = permit;
            let Ok((mut send, recv)) = connection.open_bi().await else {
                return;
            };
            if write_stream_header(&mut send, &header).await.is_err() {
                return;
            }
            let tunnel = tokio::io::join(recv, send);
            let _copied = copy_bidirectional_idle(public_stream, tunnel).await;
        }
        .instrument(span),
    );
}

const fn stream_bind(header: &StreamHeader) -> uuid::Uuid {
    match header {
        StreamHeader::Http { bind, .. } | StreamHeader::Tcp { bind, .. } => *bind,
    }
}

async fn open_http_stream(
    connection: quinn::Connection,
    header: StreamHeader,
    mut request_body: mpsc::Receiver<Result<bytes::Bytes, String>>,
    upgrade: bool,
) -> Result<OpenedHttp, String> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(|error| error.to_string())?;
    write_stream_header(&mut send, &header).await.map_err(|error| error.to_string())?;
    if upgrade {
        copy_request_body(&mut send, &mut request_body).await?;
        let head = timed_response_head(&mut recv).await?;
        if head.status == 101 {
            let (body_tx, body) = mpsc::channel(1);
            drop(body_tx);
            let (release, released) = oneshot::channel();
            return Ok(OpenedHttp::Upgrade {
                response: HttpTunnelResponse {
                    head,
                    body,
                    upgrade: Some(UpgradeTunnel { release, recv, send }),
                },
                released,
            });
        }
        let _finished = send.finish();
        return Ok(body_response(head, recv));
    }
    tokio::spawn(async move {
        if copy_request_body(&mut send, &mut request_body).await.is_ok() {
            let _finished = send.finish();
        }
    });
    let head = timed_response_head(&mut recv).await?;
    Ok(body_response(head, recv))
}

async fn timed_response_head(recv: &mut quinn::RecvStream) -> Result<HttpResponseHead, String> {
    tokio::time::timeout(RESPONSE_HEADER_TIMEOUT, read_response_head(recv))
        .await
        .map_err(|_| "response header timeout".to_owned())?
        .map_err(|error| error.to_string())
}

async fn copy_request_body(
    send: &mut quinn::SendStream,
    body: &mut mpsc::Receiver<Result<bytes::Bytes, String>>,
) -> Result<(), String> {
    loop {
        match tokio::time::timeout(DATA_IDLE_TIMEOUT, body.recv()).await {
            Ok(Some(Ok(chunk))) => {
                tokio::time::timeout(DATA_IDLE_TIMEOUT, send.write_all(&chunk))
                    .await
                    .map_err(|_| "request body idle timeout".to_owned())?
                    .map_err(|error| error.to_string())?;
            }
            Ok(Some(Err(error))) => return Err(error),
            Ok(None) => return Ok(()),
            Err(_) => return Err("request body idle timeout".to_owned()),
        }
    }
}

fn body_response(head: HttpResponseHead, recv: quinn::RecvStream) -> OpenedHttp {
    let (sender, body) = mpsc::channel(16);
    OpenedHttp::Body { response: HttpTunnelResponse { head, body, upgrade: None }, sender, recv }
}

async fn stream_response_body(
    mut recv: quinn::RecvStream,
    sender: mpsc::Sender<Result<bytes::Bytes, String>>,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(DATA_IDLE_TIMEOUT, recv.read(&mut buffer)).await;
        match read {
            Ok(Ok(None)) => return,
            Ok(Ok(Some(length))) => {
                let chunk = bytes::Bytes::copy_from_slice(&buffer[..length]);
                if sender.send(Ok(chunk)).await.is_err() {
                    let _stopped = recv.stop(0_u32.into());
                    return;
                }
            }
            Ok(Err(error)) => {
                let _sent = sender.send(Err(error.to_string())).await;
                return;
            }
            Err(_) => {
                let _sent = sender.send(Err("response body idle timeout".to_owned())).await;
                let _stopped = recv.stop(0_u32.into());
                return;
            }
        }
    }
}

pub async fn copy_bidirectional_idle<A, B>(left: A, right: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let mut left = ActivityIo::new(left, Arc::clone(&activity));
    let mut right = ActivityIo::new(right, Arc::clone(&activity));
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut left, &mut right) => result,
        () = idle_watchdog(activity) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "tunnel idle timeout",
        )),
    }
}

async fn idle_watchdog(activity: Arc<Mutex<tokio::time::Instant>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if activity.lock().elapsed() >= DATA_IDLE_TIMEOUT {
            return;
        }
    }
}

struct ActivityIo<T> {
    inner: T,
    activity: Arc<Mutex<tokio::time::Instant>>,
}

impl<T> ActivityIo<T> {
    const fn new(inner: T, activity: Arc<Mutex<tokio::time::Instant>>) -> Self {
        Self { inner, activity }
    }

    fn touch(&self) {
        *self.activity.lock() = tokio::time::Instant::now();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.touch();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.touch();
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

enum OpenedHttp {
    Body {
        response: HttpTunnelResponse,
        sender: mpsc::Sender<Result<bytes::Bytes, String>>,
        recv: quinn::RecvStream,
    },
    Upgrade {
        response: HttpTunnelResponse,
        released: oneshot::Receiver<()>,
    },
}
