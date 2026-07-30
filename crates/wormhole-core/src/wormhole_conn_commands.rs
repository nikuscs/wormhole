//! Administrative commands on an established relay connection.

use std::time::Duration;

use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    error::DriverError,
    wormhole_conn::{ConnCommand, RemoteConn},
};

impl RemoteConn {
    pub async fn unbind(&self, bind: Uuid, forget: bool) -> Result<(), DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ConnCommand::Unbind { bind, forget, reply })
            .await
            .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))?;
        tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .map_err(|_| DriverError::Transport("unbind acknowledgement timed out".to_owned()))?
            .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))
    }

    pub async fn forget_reservation(&self, reservation: Uuid) -> Result<(), DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ConnCommand::ForgetReservation { reservation, reply })
            .await
            .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))?;
        tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .map_err(|_| DriverError::Transport("forget acknowledgement timed out".to_owned()))?
            .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))
    }

    pub async fn shutdown(&self) {
        let _sent = self.commands.send(ConnCommand::Shutdown).await;
    }
}
