//! Stable loopback indirection used by `wormhole run`.

use std::net::{Ipv4Addr, SocketAddr};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub struct LocalProxy {
    address: SocketAddr,
    target: watch::Sender<SocketAddr>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl LocalProxy {
    pub async fn bind(target: SocketAddr) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (target_tx, target_rx) = watch::channel(target);
        let stop = CancellationToken::new();
        let task = tokio::spawn(accept_loop(listener, target_rx, stop.child_token()));
        Ok(Self { address, target: target_tx, stop, task })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn retarget(&self, target: SocketAddr) {
        self.target.send_replace(target);
    }

    pub async fn close(self) {
        self.stop.cancel();
        let _joined = self.task.await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    target: watch::Receiver<SocketAddr>,
    stop: CancellationToken,
) {
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => {
                let Ok((incoming, _)) = accepted else { return };
                let destination = *target.borrow();
                tokio::spawn(forward(incoming, destination));
            }
        }
    }
}

async fn forward(mut incoming: TcpStream, destination: SocketAddr) {
    let Ok(mut outgoing) = TcpStream::connect(destination).await else {
        return;
    };
    let _copied = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
}
