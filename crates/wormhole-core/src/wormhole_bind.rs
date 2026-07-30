//! Wormhole relay bind-frame translation and cancellation policy.

use uuid::Uuid;
use wormhole_proto::frames::BindSpec;

use crate::model::{EndpointSpec, ServiceProto};

pub const fn should_forget_cancelled(reservation: Option<Uuid>) -> bool {
    reservation.is_none()
}

pub const fn should_forget_bind(default: bool, requested: bool) -> bool {
    default || requested
}

pub fn bind_spec(spec: &EndpointSpec) -> BindSpec {
    match spec.proto {
        ServiceProto::Http => BindSpec::Http {
            host: spec.host.clone(),
            auto_host: spec.auto_host,
            domain: spec.domain.clone(),
            persist: spec.persist,
            buffer: spec.buffer.clone(),
            auth: spec.auth.clone(),
        },
        ServiceProto::Tcp => BindSpec::Tcp { remote_port: spec.public_port, persist: spec.persist },
    }
}
