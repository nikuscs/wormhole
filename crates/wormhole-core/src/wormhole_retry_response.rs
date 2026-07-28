//! Deadline-bounded local response spooling for retryable requests.

use http_body_util::BodyExt as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::{
    capture::CaptureContext, error::DriverError, wormhole_http::response_head,
    wormhole_stream::AbortTask,
};

pub struct SpooledResponse {
    head: wormhole_proto::frames::HttpResponseHead,
    file: tokio::fs::File,
}

pub async fn spool_retry_response(
    mut response: hyper::Response<hyper::body::Incoming>,
    _connection_task: AbortTask,
    deadline: tokio::time::Instant,
) -> Result<SpooledResponse, DriverError> {
    let file = tempfile::tempfile().map_err(transport)?;
    let mut spool = tokio::fs::File::from_std(file);
    loop {
        let frame = tokio::time::timeout_at(deadline, response.body_mut().frame())
            .await
            .map_err(|_| DriverError::LocalDelivery("local delivery deadline exceeded".to_owned()))?
            .transpose()
            .map_err(|error| DriverError::LocalDelivery(error.to_string()))?;
        let Some(frame) = frame else {
            break;
        };
        if let Ok(data) = frame.into_data() {
            spool.write_all(&data).await.map_err(transport)?;
        }
    }
    Ok(SpooledResponse { head: response_head(&response, false), file: spool })
}

pub async fn forward_spooled_response(
    send: &mut crate::wormhole_stream::BoxWrite,
    mut response: SpooledResponse,
    capture: Option<&CaptureContext>,
) -> Result<(), DriverError> {
    if let Some(context) = capture {
        context.response_head(&response.head);
    }
    wormhole_proto::codec::write_response_head(send, &response.head)
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))?;
    response.file.rewind().await.map_err(transport)?;
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let length = response.file.read(&mut buffer).await.map_err(transport)?;
        if length == 0 {
            break;
        }
        if let Some(context) = capture {
            context.response_bytes(&buffer[..length]);
        }
        send.write_all(&buffer[..length]).await.map_err(transport)?;
    }
    Ok(())
}

fn transport(error: impl std::fmt::Display) -> DriverError {
    DriverError::Transport(error.to_string())
}
