use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use http_body_util::{BodyExt as _, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;

pub struct UploadServer {
    address: SocketAddr,
    uploaded: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl UploadServer {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let worker = listener.try_clone()?;
        let uploaded = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_uploaded = Arc::clone(&uploaded);
        let worker_stop = Arc::clone(&stop);
        let task = thread::spawn(move || serve(worker, worker_uploaded, worker_stop));
        Ok(Self { address, uploaded, stop, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn uploaded(&self) -> usize {
        self.uploaded.load(Ordering::Acquire)
    }
}

impl Drop for UploadServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _wake = TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
    }
}

fn serve(listener: TcpListener, uploaded: Arc<AtomicUsize>, stop: Arc<AtomicBool>) {
    tokio::runtime::Runtime::new().expect("upload runtime").block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("upload listener");
        while !stop.load(Ordering::Acquire) {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let uploaded = Arc::clone(&uploaded);
            tokio::spawn(async move {
                let service = service_fn(move |request| upload(request, Arc::clone(&uploaded)));
                let _served =
                    http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
}

async fn upload(
    mut request: Request<Incoming>,
    uploaded: Arc<AtomicUsize>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    while let Some(frame) = request.body_mut().frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    uploaded.fetch_add(data.len(), Ordering::AcqRel);
                }
            }
            Err(error) => {
                return Ok(Response::builder()
                    .status(400)
                    .body(Full::new(bytes::Bytes::from(error.to_string())))
                    .expect("error response"));
            }
        }
    }
    Ok(Response::new(Full::new(bytes::Bytes::from_static(b"ok"))))
}
