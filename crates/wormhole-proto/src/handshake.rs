//! Pure client and server state machines for the signed-nonce handshake.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::Rng;
use uuid::Uuid;

use crate::{
    error::ProtoError,
    frames::{ControlFrame, DenyReason, Limits, PROTO_VERSION},
    keys::{Identity, decode_nonce, verify_challenge},
};

/// Successful handshake metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// Relay-assigned session identifier.
    pub session: Uuid,
    /// Limits applied to the authenticated session.
    pub limits: Limits,
    /// Optional relay message.
    pub motd: Option<String>,
}

/// Result of advancing either handshake machine by one incoming frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeStep {
    /// Send this frame and await the peer's next handshake frame.
    Reply(ControlFrame),
    /// Handshake completed; the server includes its final Welcome reply.
    Done { welcome: Welcome, reply: Option<ControlFrame> },
    /// Handshake failed; the server includes its final Denied reply.
    Failed { reason: DenyReason, reply: Option<ControlFrame> },
}

/// Authorization decision for a presented public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDecision {
    /// The key may establish sessions.
    Authorized,
    /// The key is not in the authorized set.
    Unknown,
    /// The key was explicitly revoked.
    Revoked,
    /// Policy limits currently reject the key.
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    AwaitingChallenge,
    AwaitingWelcome,
    Done,
    Failed,
}

/// Client side of the version 1 handshake.
pub struct ClientHandshake {
    identity: Identity,
    server_name: String,
    client_name: String,
    state: ClientState,
}

impl ClientHandshake {
    /// Creates a client handshake bound to one configured relay name.
    pub fn new(
        identity: Identity,
        server_name: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            server_name: server_name.into(),
            client_name: client_name.into(),
            state: ClientState::AwaitingChallenge,
        }
    }

    /// Returns the opening Hello frame.
    pub fn hello(&self) -> ControlFrame {
        ControlFrame::Hello {
            proto: PROTO_VERSION,
            client: self.client_name.clone(),
            pubkey: self.identity.public_base64(),
        }
    }

    /// Advances the client with one server frame.
    pub fn step(&mut self, incoming: &ControlFrame) -> Result<HandshakeStep, ProtoError> {
        match (self.state, incoming) {
            (ClientState::AwaitingChallenge, ControlFrame::Challenge { nonce, server }) => {
                self.answer_challenge(nonce, server)
            }
            (
                ClientState::AwaitingChallenge | ClientState::AwaitingWelcome,
                ControlFrame::Denied { reason },
            ) => {
                self.state = ClientState::Failed;
                Ok(HandshakeStep::Failed { reason: reason.clone(), reply: None })
            }
            (ClientState::AwaitingWelcome, ControlFrame::Welcome { session, limits, motd }) => {
                self.state = ClientState::Done;
                Ok(HandshakeStep::Done {
                    welcome: Welcome {
                        session: *session,
                        limits: limits.clone(),
                        motd: motd.clone(),
                    },
                    reply: None,
                })
            }
            _ => self.protocol_error(incoming),
        }
    }

    fn answer_challenge(
        &mut self,
        encoded_nonce: &str,
        server: &str,
    ) -> Result<HandshakeStep, ProtoError> {
        if server != self.server_name {
            self.state = ClientState::Failed;
            return Err(ProtoError::ServerNameMismatch {
                expected: self.server_name.clone(),
                actual: server.to_owned(),
            });
        }
        let nonce = decode_nonce(encoded_nonce).map_err(|_| {
            self.state = ClientState::Failed;
            ProtoError::Protocol("challenge nonce must be 32-byte base64".to_owned())
        })?;
        let signature = self.identity.sign_challenge(&nonce, server, PROTO_VERSION);
        self.state = ClientState::AwaitingWelcome;
        Ok(HandshakeStep::Reply(ControlFrame::Auth { signature }))
    }

    fn protocol_error(&mut self, incoming: &ControlFrame) -> Result<HandshakeStep, ProtoError> {
        self.state = ClientState::Failed;
        Err(ProtoError::Protocol(format!(
            "unexpected {} while client is {:?}",
            frame_name(incoming),
            self.state
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    AwaitingHello,
    AwaitingAuth,
    Done,
    Failed,
}

/// Server side of the version 1 handshake.
pub struct ServerHandshake<F> {
    server_name: String,
    limits: Limits,
    motd: Option<String>,
    is_authorized: F,
    state: ServerState,
    nonce: Option<[u8; 32]>,
    public_key: Option<String>,
}

impl<F: Fn(&str) -> KeyDecision> ServerHandshake<F> {
    /// Creates a relay handshake using the supplied public-key authorization callback.
    pub fn new(
        server_name: impl Into<String>,
        limits: Limits,
        motd: Option<String>,
        is_authorized: F,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            limits,
            motd,
            is_authorized,
            state: ServerState::AwaitingHello,
            nonce: None,
            public_key: None,
        }
    }

    /// Advances the server with one client frame.
    pub fn step(&mut self, incoming: &ControlFrame) -> Result<HandshakeStep, ProtoError> {
        match (self.state, incoming) {
            (ServerState::AwaitingHello, ControlFrame::Hello { proto, pubkey, .. }) => {
                Ok(self.accept_hello(*proto, pubkey))
            }
            (ServerState::AwaitingAuth, ControlFrame::Auth { signature }) => {
                self.verify_auth(signature)
            }
            _ => self.protocol_error(incoming),
        }
    }

    fn accept_hello(&mut self, proto: u16, public_key: &str) -> HandshakeStep {
        if proto != PROTO_VERSION {
            return self.deny(DenyReason::VersionMismatch { expected: PROTO_VERSION });
        }
        match (self.is_authorized)(public_key) {
            KeyDecision::Authorized => {}
            KeyDecision::Unknown => return self.deny(DenyReason::UnknownKey),
            KeyDecision::Revoked => return self.deny(DenyReason::KeyRevoked),
            KeyDecision::Limit => return self.deny(DenyReason::Limit),
        }
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        self.nonce = Some(nonce);
        self.public_key = Some(public_key.to_owned());
        self.state = ServerState::AwaitingAuth;
        HandshakeStep::Reply(ControlFrame::Challenge {
            nonce: STANDARD.encode(nonce),
            server: self.server_name.clone(),
        })
    }

    fn verify_auth(&mut self, signature: &str) -> Result<HandshakeStep, ProtoError> {
        let nonce = self
            .nonce
            .ok_or_else(|| ProtoError::Protocol("server challenge nonce is missing".to_owned()))?;
        let public_key = self
            .public_key
            .as_deref()
            .ok_or_else(|| ProtoError::Protocol("server public key is missing".to_owned()))?;
        if !verify_challenge(public_key, &nonce, &self.server_name, PROTO_VERSION, signature) {
            return Ok(self.deny(DenyReason::BadSignature));
        }
        self.state = ServerState::Done;
        let welcome = Welcome {
            session: Uuid::now_v7(),
            limits: self.limits.clone(),
            motd: self.motd.clone(),
        };
        let reply = welcome_frame(&welcome);
        Ok(HandshakeStep::Done { welcome, reply: Some(reply) })
    }

    fn deny(&mut self, reason: DenyReason) -> HandshakeStep {
        self.state = ServerState::Failed;
        HandshakeStep::Failed {
            reply: Some(ControlFrame::Denied { reason: reason.clone() }),
            reason,
        }
    }

    fn protocol_error(&mut self, incoming: &ControlFrame) -> Result<HandshakeStep, ProtoError> {
        let state = self.state;
        self.state = ServerState::Failed;
        Err(ProtoError::Protocol(format!(
            "unexpected {} while server is {state:?}",
            frame_name(incoming)
        )))
    }
}

fn welcome_frame(welcome: &Welcome) -> ControlFrame {
    ControlFrame::Welcome {
        session: welcome.session,
        limits: welcome.limits.clone(),
        motd: welcome.motd.clone(),
    }
}

const fn frame_name(frame: &ControlFrame) -> &'static str {
    match frame {
        ControlFrame::Hello { .. } => "hello",
        ControlFrame::Challenge { .. } => "challenge",
        ControlFrame::Auth { .. } => "auth",
        ControlFrame::Welcome { .. } => "welcome",
        ControlFrame::Denied { .. } => "denied",
        ControlFrame::Bind { .. } => "bind",
        ControlFrame::Unbind { .. } => "unbind",
        ControlFrame::BindReady { .. } => "bind_ready",
        ControlFrame::Bound { .. } => "bound",
        ControlFrame::BindError { .. } => "bind_error",
        ControlFrame::BindActive { .. } => "bind_active",
        ControlFrame::Event { .. } => "event",
        ControlFrame::AckBuffered { .. } => "ack_buffered",
        ControlFrame::NackBuffered { .. } => "nack_buffered",
        ControlFrame::Ping { .. } => "ping",
        ControlFrame::Pong { .. } => "pong",
    }
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
