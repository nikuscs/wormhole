use std::sync::Arc;

use tokio::{
    io::DuplexStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
};

use crate::{frames::StreamHeader, mux_runtime::MuxRuntimeError};

pub struct ChannelRuntime {
    pub writer: mpsc::Sender<WriterCommand>,
    pub writer_task: tokio::task::JoinHandle<()>,
    pub reader_abort: tokio::task::AbortHandle,
    pub ready: Arc<tokio::sync::Notify>,
    pub send_credit: Option<Arc<Semaphore>>,
    pub writer_closed: bool,
}

pub enum WriterCommand {
    Data(Vec<u8>, Option<OwnedSemaphorePermit>),
    Header(StreamHeader),
    Shutdown,
}

pub enum Command {
    Open { header: StreamHeader, reply: oneshot::Sender<Result<DuplexStream, MuxRuntimeError>> },
    Data { channel: u32, payload: Vec<u8>, budget: Option<OwnedSemaphorePermit> },
    Fin { channel: u32 },
    WriterClosed { channel: u32, failed: bool },
}

pub struct ActorIo {
    pub commands: mpsc::Sender<Command>,
    pub network: mpsc::Receiver<Vec<u8>>,
    pub outbound: mpsc::Sender<Vec<u8>>,
    pub incoming: mpsc::Sender<DuplexStream>,
    pub writer_budget: Arc<Semaphore>,
    pub outbound_budget: Arc<Semaphore>,
}
