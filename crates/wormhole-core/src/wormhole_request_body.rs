//! QUIC request-body retention and streaming adapters.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use tokio::io::AsyncReadExt as _;

#[derive(Debug, thiserror::Error)]
#[error("public request body failed: {0}")]
pub struct PublicReadError(#[source] pub std::io::Error);

use crate::{
    capture::CaptureContext,
    error::DriverError,
    wormhole_stream::{BoxError, BoxRead, ClientBody},
};

pub async fn retain_request_body(
    mut recv: BoxRead,
    limit: u64,
    capture: Option<CaptureContext>,
) -> Result<(Vec<u8>, Option<BoxRead>, bool), DriverError> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut retained = Vec::new();
    loop {
        let mut buffer = vec![0_u8; 16 * 1024];
        match recv.read(&mut buffer).await {
            Ok(0) => {
                if let Some(capture) = &capture {
                    capture.complete_request();
                }
                return Ok((retained, None, true));
            }
            Ok(length) => {
                if let Some(capture) = &capture {
                    capture.request_bytes(&buffer[..length]);
                }
                retained.extend_from_slice(&buffer[..length]);
                if retained.len() > limit {
                    return Ok((retained, Some(recv), false));
                }
            }
            Err(error) => return Err(DriverError::Transport(error.to_string())),
        }
    }
}

pub fn request_body_with_prefix(
    prefix: Vec<u8>,
    recv: BoxRead,
    capture: Option<CaptureContext>,
) -> ClientBody {
    let stream = futures::stream::unfold(
        (Some(Bytes::from(prefix)), recv, capture),
        |(prefix, mut recv, capture)| async move {
            if let Some(prefix) = prefix {
                return Some((Ok(Frame::data(prefix)), (None, recv, capture)));
            }
            let mut buffer = vec![0_u8; 16 * 1024];
            match recv.read(&mut buffer).await {
                Ok(0) => {
                    if let Some(capture) = &capture {
                        capture.complete_request();
                    }
                    None
                }
                Ok(length) => {
                    if let Some(capture) = &capture {
                        capture.request_bytes(&buffer[..length]);
                    }
                    Some((
                        Ok(Frame::data(Bytes::copy_from_slice(&buffer[..length]))),
                        (None, recv, capture),
                    ))
                }
                Err(error) => Some((
                    Err::<Frame<Bytes>, BoxError>(Box::new(PublicReadError(error))),
                    (None, recv, capture),
                )),
            }
        },
    );
    StreamBody::new(stream).boxed_unsync()
}

pub fn request_body(
    recv: BoxRead,
    upgrade: bool,
    capture: Option<CaptureContext>,
) -> (ClientBody, Option<BoxRead>) {
    if upgrade {
        if let Some(capture) = &capture {
            capture.complete_request();
        }
        let body = Full::new(Bytes::new())
            .map_err(|never: Infallible| -> BoxError { match never {} })
            .boxed_unsync();
        return (body, Some(recv));
    }
    let stream = futures::stream::unfold((recv, capture), |(mut recv, capture)| async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        match recv.read(&mut buffer).await {
            Ok(0) => {
                if let Some(capture) = &capture {
                    capture.complete_request();
                }
                None
            }
            Ok(length) => {
                if let Some(capture) = &capture {
                    capture.request_bytes(&buffer[..length]);
                }
                Some((Ok(Frame::data(Bytes::copy_from_slice(&buffer[..length]))), (recv, capture)))
            }
            Err(error) => Some((
                Err::<Frame<Bytes>, BoxError>(Box::new(PublicReadError(error))),
                (recv, capture),
            )),
        }
    });
    (StreamBody::new(stream).boxed_unsync(), None)
}
