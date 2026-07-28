//! Authenticated session actor and control-frame lifecycle.

use std::{collections::HashMap, sync::Arc};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc, watch};
use uuid::Uuid;
use wormhole_proto::{
    ProtoError,
    codec::ControlChannel,
    frames::{ControlFrame, EdgeAuth, EventKind, Persistence},
};

use crate::{
    authz::KeyLimits,
    db::{AuthVerifier, PersistedBind, PersistedEndpoint},
    registry::{AllocationRequest, RegistryError, SessionCommand},
    session_streams::{DataOpener, spawn_http_stream, spawn_tcp_stream},
    state::AppState,
};

/// Runs one authenticated client's control loop and bind lifecycle.
pub struct SessionActor<S> {
    channel: ControlChannel<S>,
    opener: DataOpener,
    command_rx: mpsc::Receiver<SessionCommand>,
    session_tx: mpsc::Sender<SessionCommand>,
    state: Arc<AppState>,
    fingerprint: String,
    limits: KeyLimits,
    stream_slots: Arc<Semaphore>,
    shutdown_rx: watch::Receiver<bool>,
    binds: HashMap<Uuid, Persistence>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SessionActor<S> {
    /// Creates an authenticated session actor.
    pub fn new(
        channel: ControlChannel<S>,
        opener: DataOpener,
        state: Arc<AppState>,
        fingerprint: String,
        limits: KeyLimits,
    ) -> Self {
        let (session_tx, command_rx) = mpsc::channel(256);
        let stream_slots = Arc::new(Semaphore::new(limits.max_streams as usize));
        let shutdown_rx = state.subscribe_shutdown();
        Self {
            channel,
            opener,
            command_rx,
            session_tx,
            state,
            fingerprint,
            limits,
            stream_slots,
            shutdown_rx,
            binds: HashMap::new(),
        }
    }

    /// Runs until the control stream closes, protocol fails, or shutdown arrives.
    #[tracing::instrument(name = "session", skip_all, fields(key_fpr = %self.fingerprint))]
    pub async fn run(mut self) -> Result<(), SessionError> {
        let result = if *self.shutdown_rx.borrow() {
            self.channel
                .send(&ControlFrame::Event {
                    kind: EventKind::Shutdown,
                    msg: "relay shutting down".to_owned(),
                })
                .await
                .map_err(SessionError::from)
        } else {
            self.control_loop().await
        };
        self.cleanup();
        result
    }

    async fn control_loop(&mut self) -> Result<(), SessionError> {
        loop {
            tokio::select! {
                frame = self.channel.recv() => {
                    match frame {
                        Ok(frame) => self.handle_frame(frame).await?,
                        Err(ProtoError::Closed) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                }
                shutdown = self.shutdown_rx.changed() => {
                    if shutdown.is_ok() && *self.shutdown_rx.borrow() {
                        self.channel.send(&ControlFrame::Event {
                            kind: EventKind::Shutdown,
                            msg: "relay shutting down".to_owned(),
                        }).await?;
                    }
                    return Ok(());
                }
                command = self.command_rx.recv() => {
                    match command {
                        Some(SessionCommand::OpenHttp { header, body, upgrade, reply }) => {
                            match Arc::clone(&self.stream_slots).try_acquire_owned() {
                                Ok(permit) => spawn_http_stream(
                                    self.opener.clone(),
                                    Arc::clone(&self.state),
                                    permit,
                                    header,
                                    body,
                                    upgrade,
                                    reply,
                                ),
                                Err(_) => {
                                    let _sent = reply.send(Err("session stream limit reached".to_owned()));
                                }
                            }
                        }
                        Some(SessionCommand::OpenTcp { header, stream }) => {
                            if let Ok(permit) = Arc::clone(&self.stream_slots).try_acquire_owned() {
                                spawn_tcp_stream(
                                    self.opener.clone(),
                                    Arc::clone(&self.state),
                                    permit,
                                    header,
                                    stream,
                                );
                            }
                        }
                        Some(SessionCommand::BufferedStatus { bind, pending, failed }) => {
                            self.channel.send(&ControlFrame::BufferedStatus {
                                bind,
                                pending,
                                failed,
                            }).await?;
                        }
                        Some(SessionCommand::RemoveBind { bind }) => {
                            self.release_deleted_bind(bind);
                        }
                        Some(SessionCommand::Shutdown) => {
                            self.channel.send(&ControlFrame::Event {
                                kind: EventKind::Shutdown,
                                msg: "relay shutting down".to_owned(),
                            }).await?;
                            return Ok(());
                        }
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn handle_frame(&mut self, frame: ControlFrame) -> Result<(), SessionError> {
        match frame {
            ControlFrame::Bind { request, spec, reservation } => {
                self.handle_bind(request, spec, reservation).await
            }
            ControlFrame::BindReady { bind } => {
                self.state.registry.activate(bind, &self.session_tx)?;
                self.channel.send(&ControlFrame::BindActive { bind }).await?;
                if let Some(handle) = self.state.registry.get_bind(bind) {
                    crate::buffer::spawn_drain(Arc::clone(&self.state), handle);
                }
                Ok(())
            }
            ControlFrame::Unbind { bind, forget } => self.handle_unbind(bind, forget).await,
            ControlFrame::ForgetReservation { reservation } => {
                self.handle_forget_reservation(reservation).await
            }
            ControlFrame::AckBuffered { bind, seq } => {
                self.validate_buffered_result(bind, seq)?;
                self.state.database.delete_buffered(bind, seq)?;
                self.continue_buffered_drain(bind);
                Ok(())
            }
            ControlFrame::NackBuffered { bind, seq, reason } => {
                self.validate_buffered_result(bind, seq)?;
                self.state.database.fail_buffered(bind, seq, &reason)?;
                self.continue_buffered_drain(bind);
                Ok(())
            }
            ControlFrame::Ping { seq } => {
                self.channel.send(&ControlFrame::Pong { seq }).await?;
                Ok(())
            }
            unexpected => Err(SessionError::Protocol(format!(
                "unexpected post-handshake frame: {unexpected:?}"
            ))),
        }
    }

    #[tracing::instrument(
        name = "bind",
        skip_all,
        fields(request_id = %request_id, key_fpr = %self.fingerprint)
    )]
    async fn handle_bind(
        &mut self,
        request_id: Uuid,
        spec: wormhole_proto::frames::BindSpec,
        reservation: Option<Uuid>,
    ) -> Result<(), SessionError> {
        let is_new = reservation.is_none();
        if is_new && !self.state.try_add_bind(&self.fingerprint, self.limits.max_binds) {
            return self.send_bind_error(request_id, "global bind limit reached").await;
        }
        let allocation = self.state.registry.allocate(AllocationRequest {
            key_fpr: self.fingerprint.clone(),
            spec,
            reservation,
            session_tx: self.session_tx.clone(),
        });
        let allocation = match allocation {
            Ok(allocation) => allocation,
            Err(error) => {
                if is_new {
                    self.state.remove_bind(&self.fingerprint);
                }
                return self.send_bind_error(request_id, &error.to_string()).await;
            }
        };
        if let Some(handle) = self.state.registry.get_bind(allocation.bind)
            && let PersistedEndpoint::TcpPort(port) = handle.endpoint
            && let Err(error) = self.state.tcp_edges.ensure_listener(port, handle).await
        {
            self.rollback_allocation(allocation.bind, is_new);
            return Err(SessionError::Io(error));
        }
        if allocation.persist == Persistence::Persistent
            && let Err(error) = self.persist_bind(allocation.bind)
        {
            self.rollback_allocation(allocation.bind, is_new);
            return Err(error);
        }
        self.binds.insert(allocation.bind, allocation.persist);
        let (pending_buffered, failed_buffered) =
            self.state.database.buffered_counts(allocation.bind)?;
        self.channel
            .send(&ControlFrame::Bound {
                request: request_id,
                bind: allocation.bind,
                urls: allocation.urls,
                persist: allocation.persist,
                reservation: allocation.reservation,
                pending_buffered,
                failed_buffered,
            })
            .await?;
        Ok(())
    }

    fn persist_bind(&self, bind_id: Uuid) -> Result<(), SessionError> {
        let handle =
            self.state.registry.get_bind(bind_id).ok_or(RegistryError::UnknownBind(bind_id))?;
        let existing = self.state.database.get_bind(bind_id)?;
        let now = jiff::Timestamp::now();
        let auth_verifier = match (&handle.auth, &existing) {
            (Some(auth), _) => Some(build_auth_verifier(auth)?),
            (None, Some(existing)) => existing.auth_verifier.clone(),
            (None, None) => None,
        };
        handle.set_auth_verifier(auth_verifier.clone());
        let record = PersistedBind {
            reservation: handle.reservation.ok_or_else(|| {
                SessionError::Protocol("persistent bind lacks reservation".to_owned())
            })?,
            spec: handle.spec.clone(),
            auth_verifier,
            endpoint: handle.endpoint.clone(),
            key_fpr: self.fingerprint.clone(),
            created: existing.as_ref().map_or(now, |record| record.created),
            last_seen: now,
        };
        self.state.database.put_bind(bind_id, &record)?;
        Ok(())
    }

    fn rollback_allocation(&self, bind: Uuid, is_new: bool) {
        if is_new {
            let _ignored = self.state.registry.remove(bind, true);
            self.state.remove_bind(&self.fingerprint);
        } else {
            let _ignored = self.state.registry.disconnect(bind);
        }
    }

    async fn send_bind_error(&mut self, request: Uuid, reason: &str) -> Result<(), SessionError> {
        self.channel.send(&ControlFrame::BindError { request, reason: reason.to_owned() }).await?;
        Ok(())
    }

    fn validate_buffered_result(&self, bind: Uuid, seq: u64) -> Result<(), SessionError> {
        if !self.binds.contains_key(&bind) || !self.state.complete_buffered(bind, seq) {
            return Err(SessionError::Protocol(format!(
                "buffered result is not in flight for this session: {bind}/{seq}"
            )));
        }
        Ok(())
    }

    fn continue_buffered_drain(&self, bind: Uuid) {
        if let Some(handle) = self.state.registry.get_bind(bind) {
            crate::buffer::spawn_drain(Arc::clone(&self.state), handle);
        }
    }

    async fn handle_unbind(&mut self, bind: Uuid, forget: bool) -> Result<(), SessionError> {
        let persist = self.binds.remove(&bind).ok_or(RegistryError::UnknownBind(bind))?;
        self.state.release_buffered_bind(bind);
        let tcp_port = self.tcp_port(bind);
        match (persist, forget) {
            (Persistence::Persistent, false) => self.state.registry.disconnect(bind)?,
            (Persistence::Persistent, true) => {
                if let Some(port) = tcp_port {
                    self.state.tcp_edges.remove_listener(port);
                }
                self.state.registry.remove(bind, true)?;
                self.state.database.delete_bind_data(bind)?;
                self.state.remove_bind(&self.fingerprint);
            }
            (Persistence::Temporary, _) => {
                if let Some(port) = tcp_port {
                    self.state.tcp_edges.remove_listener(port);
                }
                self.state.registry.remove(bind, true)?;
                self.state.remove_bind(&self.fingerprint);
            }
        }
        self.channel.send(&ControlFrame::Unbound { bind }).await?;
        Ok(())
    }

    async fn handle_forget_reservation(&mut self, reservation: Uuid) -> Result<(), SessionError> {
        if let Some(bind) = self.state.registry.bind_for_reservation(reservation) {
            let handle =
                self.state.registry.get_bind(bind).ok_or(RegistryError::UnknownBind(bind))?;
            if handle.key_fpr != self.fingerprint {
                return Err(RegistryError::ReservationOwnerMismatch.into());
            }
            if let Some(port) = self.tcp_port(bind) {
                self.state.tcp_edges.remove_listener(port);
            }
            self.binds.remove(&bind);
            self.state.release_buffered_bind(bind);
            self.state.registry.remove(bind, true)?;
            self.state.database.delete_bind_data(bind)?;
            self.state.remove_bind(&self.fingerprint);
        }
        self.channel.send(&ControlFrame::ForgotReservation { reservation }).await?;
        Ok(())
    }

    fn tcp_port(&self, bind: Uuid) -> Option<u16> {
        self.state.registry.get_bind(bind).and_then(|handle| match handle.endpoint {
            PersistedEndpoint::TcpPort(port) => Some(port),
            PersistedEndpoint::Hostname(_) => None,
        })
    }

    fn release_deleted_bind(&mut self, bind: Uuid) {
        self.state.release_buffered_bind(bind);
        if self.binds.remove(&bind).is_none() {
            return;
        }
        self.state.remove_bind(&self.fingerprint);
    }

    fn cleanup(&mut self) {
        let binds = self.binds.drain().collect::<Vec<_>>();
        for (bind, persist) in binds {
            self.state.release_buffered_bind(bind);
            match persist {
                Persistence::Persistent => {
                    let _ignored = self.state.registry.disconnect(bind);
                }
                Persistence::Temporary => {
                    if let Some(port) = self.tcp_port(bind) {
                        self.state.tcp_edges.remove_listener(port);
                    }
                    let _ignored = self.state.registry.remove(bind, true);
                    self.state.remove_bind(&self.fingerprint);
                }
            }
        }
    }
}

fn build_auth_verifier(auth: &EdgeAuth) -> Result<AuthVerifier, SessionError> {
    let basic_argon2 = auth
        .basic
        .as_deref()
        .map(|credential| {
            let (username, password) = credential.split_once(':').ok_or_else(|| {
                SessionError::Protocol("basic auth must be user:password".to_owned())
            })?;
            let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())
                .map_err(|error| SessionError::Auth(error.to_string()))?;
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|error| SessionError::Auth(error.to_string()))?;
            Ok::<_, SessionError>(format!("{username}:{hash}"))
        })
        .transpose()?;
    let bearer_sha256 =
        auth.bearer.as_deref().map(|token| STANDARD.encode(Sha256::digest(token.as_bytes())));
    Ok(AuthVerifier { basic_argon2, bearer_sha256, link_hmac_key: auth.link_key.clone() })
}

/// Session control or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Wire protocol failed.
    #[error(transparent)]
    ProtocolIo(#[from] ProtoError),
    /// Post-handshake protocol ordering failed.
    #[error("session protocol violation: {0}")]
    Protocol(String),
    /// Registry allocation or transition failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Database operation failed.
    #[error(transparent)]
    Database(#[from] crate::db::DbError),
    /// Edge-auth verifier construction failed.
    #[error("edge auth verifier failed: {0}")]
    Auth(String),
    /// TCP listener setup failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
