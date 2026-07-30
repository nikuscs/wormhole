//! Automatic Tailscale Serve port selection and conflict recovery.

use crate::{
    drivers::{
        tailscale::TailscaleDriver, tailscale_args::public_port, tailscale_state::BindingClaim,
    },
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

const MAX_PORT_ATTEMPTS: usize = 32;

impl TailscaleDriver {
    pub(super) fn claim_binding<'a>(
        &'a self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<BindingClaim<'a>, DriverError> {
        let key = public_port(spec, target).to_string();
        self.active.claim(self.ownership_dir.as_deref(), key)
    }

    pub(super) async fn select_binding<'a>(
        &'a self,
        spec: &mut EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<BindingClaim<'a>, DriverError> {
        let automatic = spec.proto == ServiceProto::Http
            && spec.qualifier.is_none()
            && spec.public_port.is_none();
        if !automatic {
            return self.claim_checked(spec, target).await;
        }

        let initial_port = public_port(spec, target);
        let candidates = std::iter::once(initial_port)
            .chain(
                (self.https_port_range.start..=self.https_port_range.end)
                    .filter(|port| *port != initial_port),
            )
            .take(MAX_PORT_ATTEMPTS);
        let mut last_conflict = None;
        for port in candidates {
            spec.public_port = Some(port);
            let claim = self.claim_binding(spec, target)?;
            match self.reject_conflict("serve", spec, target).await {
                Ok(()) => return Ok(claim),
                Err(error @ DriverError::Capability(_)) => {
                    last_conflict = Some(error);
                    drop(claim);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_conflict.unwrap_or_else(|| {
            DriverError::Capability("no automatic tailscale Serve ports available".to_owned())
        }))
    }

    async fn claim_checked<'a>(
        &'a self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<BindingClaim<'a>, DriverError> {
        let claim = self.claim_binding(spec, target)?;
        let mode = spec.qualifier.as_deref().map_or("serve", |_| "funnel");
        self.reject_conflict(mode, spec, target).await?;
        Ok(claim)
    }
}
