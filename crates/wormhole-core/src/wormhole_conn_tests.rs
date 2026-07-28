use uuid::Uuid;

use super::{bind_spec, should_forget_bind, should_forget_cancelled};
use crate::model::{EndpointSpec, ServiceProto};
use wormhole_proto::frames::{BindSpec, Persistence};

#[test]
fn bind_specs_preserve_http_and_tcp_options() {
    let mut spec: EndpointSpec = serde_json::from_str(
        r#"{"proto":"http","driver":"wormhole","host":"app","domain":"example.com","persist":"persistent","inspect":false}"#,
    )
    .expect("HTTP spec");
    assert!(matches!(
        bind_spec(&spec),
        BindSpec::Http { host: Some(host), domain: Some(domain), persist: Persistence::Persistent, .. }
            if host == "app" && domain == "example.com"
    ));
    spec.proto = ServiceProto::Tcp;
    spec.public_port = Some(5432);
    assert!(matches!(
        bind_spec(&spec),
        BindSpec::Tcp { remote_port: Some(5432), persist: Persistence::Persistent }
    ));
}

#[test]
fn cancelled_reclaim_preserves_existing_reservation() {
    assert!(should_forget_cancelled(None));
    assert!(!should_forget_cancelled(Some(Uuid::now_v7())));
    assert!(should_forget_bind(false, true));
    assert!(should_forget_bind(true, false));
    assert!(!should_forget_bind(false, false));
}
