//! QUIC request-body retention and streaming adapters.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;

use crate::{
    capture::CaptureContext,
    error::DriverError,
    wormhole_stream::{BoxError, ClientBody},
};

pub async fn retain_request_body(
    mut recv: quinn::RecvStream,
    limit: u64,
    capture: Option<CaptureContext>,
) -> Result<(Vec<u8>, Option<quinn::RecvStream>, bool), DriverError> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut retained = Vec::new();
    loop {
        let mut buffer = vec![0_u8; 16 * 1024];
        match recv.read(&mut buffer).await {
            Ok(None) => {
                if let Some(capture) = &capture {
                    capture.complete_request();
                }
                return Ok((retained, None, true));
            }
            Ok(Some(length)) => {
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
    recv: quinn::RecvStream,
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
                Ok(None) => {
                    if let Some(capture) = &capture {
                        capture.complete_request();
                    }
                    None
                }
                Ok(Some(length)) => {
                    if let Some(capture) = &capture {
                        capture.request_bytes(&buffer[..length]);
                    }
                    Some((
                        Ok(Frame::data(Bytes::copy_from_slice(&buffer[..length]))),
                        (None, recv, capture),
                    ))
                }
                Err(error) => {
                    Some((Err::<Frame<Bytes>, BoxError>(Box::new(error)), (None, recv, capture)))
                }
            }
        },
    );
    StreamBody::new(stream).boxed_unsync()
}

pub fn request_body(
    recv: quinn::RecvStream,
    upgrade: bool,
    capture: Option<CaptureContext>,
) -> (ClientBody, Option<quinn::RecvStream>) {
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
            Ok(None) => {
                if let Some(capture) = &capture {
                    capture.complete_request();
                }
                None
            }
            Ok(Some(length)) => {
                if let Some(capture) = &capture {
                    capture.request_bytes(&buffer[..length]);
                }
                Some((Ok(Frame::data(Bytes::copy_from_slice(&buffer[..length]))), (recv, capture)))
            }
            Err(error) => Some((Err::<Frame<Bytes>, BoxError>(Box::new(error)), (recv, capture))),
        }
    });
    (StreamBody::new(stream).boxed_unsync(), None)
}
