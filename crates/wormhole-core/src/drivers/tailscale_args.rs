//! Tailscale Serve and Funnel argument and public URL construction.

use crate::model::{EndpointSpec, ResolvedTarget, ServiceProto};

pub(super) fn install_args(
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
    background: bool,
) -> Vec<String> {
    let mut args = vec![mode.to_owned()];
    if background {
        args.push("--bg".to_owned());
    }
    if spec.proto == ServiceProto::Tcp {
        args.push(format!("--tcp={}", public_port(spec, target)));
        args.push(format!("tcp://{}", target.0));
    } else {
        if let Some(port) = spec.public_port {
            args.push(format!("--https={port}"));
        }
        args.push(format!("http://{}", target.0));
    }
    args
}

pub(super) fn public_port(spec: &EndpointSpec, target: ResolvedTarget) -> u16 {
    if spec.proto == ServiceProto::Http {
        spec.public_port.unwrap_or(443)
    } else {
        spec.public_port.unwrap_or_else(|| target.0.port())
    }
}

pub(super) fn public_url(proto: ServiceProto, dns: &str, port: u16) -> String {
    match (proto, port) {
        (ServiceProto::Http, 443) => format!("https://{dns}"),
        (ServiceProto::Http, _) => format!("https://{dns}:{port}"),
        (ServiceProto::Tcp, _) => format!("tcp://{dns}:{port}"),
    }
}
