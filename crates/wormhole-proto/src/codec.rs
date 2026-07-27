//! Bounded length-delimited JSON codecs shared by clients and relays.

use std::io;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{
    error::ProtoError,
    frames::{ControlFrame, HttpResponseHead, StreamHeader},
};

const CONTROL_FRAME_LIMIT: usize = 1024 * 1024;
const DATA_HEAD_LIMIT: usize = 64 * 1024;

/// A bounded framed control stream.
pub struct ControlChannel<S> {
    framed: Framed<S, LengthDelimitedCodec>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlChannel<S> {
    /// Wraps an I/O stream with the protocol's 4-byte big-endian framing.
    pub fn new(io: S) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .big_endian()
            .max_frame_length(CONTROL_FRAME_LIMIT)
            .new_codec();
        Self { framed: Framed::new(io, codec) }
    }

    /// Serializes and sends one control frame.
    pub async fn send(&mut self, frame: &ControlFrame) -> Result<(), ProtoError> {
        let encoded = serde_json::to_vec(frame)?;
        ensure_limit(encoded.len(), CONTROL_FRAME_LIMIT)?;
        self.framed.send(Bytes::from(encoded)).await.map_err(ProtoError::Io)
    }

    /// Receives and decodes one control frame.
    pub async fn recv(&mut self) -> Result<ControlFrame, ProtoError> {
        match self.framed.next().await {
            Some(Ok(bytes)) => Ok(serde_json::from_slice(&bytes)?),
            Some(Err(error)) => Err(map_control_error(error)),
            None => Err(ProtoError::Closed),
        }
    }
}

/// Writes a bounded stream header.
pub async fn write_stream_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &StreamHeader,
) -> Result<(), ProtoError> {
    write_json_head(writer, header).await
}

/// Reads a bounded stream header.
pub async fn read_stream_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<StreamHeader, ProtoError> {
    read_json_head(reader).await
}

/// Writes a bounded HTTP response head.
pub async fn write_response_head<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &HttpResponseHead,
) -> Result<(), ProtoError> {
    write_json_head(writer, head).await
}

/// Reads a bounded HTTP response head.
pub async fn read_response_head<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<HttpResponseHead, ProtoError> {
    read_json_head(reader).await
}

async fn write_json_head<W, T>(writer: &mut W, value: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = serde_json::to_vec(value)?;
    ensure_limit(encoded.len(), DATA_HEAD_LIMIT)?;
    let length = u32::try_from(encoded.len())
        .map_err(|_| ProtoError::FrameTooLarge { limit: DATA_HEAD_LIMIT })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&encoded).await?;
    Ok(())
}

async fn read_json_head<R, T>(reader: &mut R) -> Result<T, ProtoError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).await?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| ProtoError::FrameTooLarge { limit: DATA_HEAD_LIMIT })?;
    ensure_limit(length, DATA_HEAD_LIMIT)?;
    let mut encoded = vec![0_u8; length];
    reader.read_exact(&mut encoded).await?;
    Ok(serde_json::from_slice(&encoded)?)
}

const fn ensure_limit(length: usize, limit: usize) -> Result<(), ProtoError> {
    if length > limit {
        return Err(ProtoError::FrameTooLarge { limit });
    }
    Ok(())
}

fn map_control_error(error: io::Error) -> ProtoError {
    if error.kind() == io::ErrorKind::InvalidData {
        ProtoError::FrameTooLarge { limit: CONTROL_FRAME_LIMIT }
    } else {
        ProtoError::Io(error)
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
