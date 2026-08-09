use std::sync::Arc;

use wormhole_core::{
    ActiveEndpoint, ClientConfig, Service, Target,
    config::HttpsPortRange,
    driver::DriverRegistry,
    model::{EndpointStatus, ServiceProto},
};
use wormhole_proto::frames::Persistence;

use crate::cli::TunnelOptions;

use super::{
    build_specs, endpoint_result, parse_target, resolve_target, start_foreground_with_registry,
};

#[test]
fn targets_distinguish_ports_hosts_and_interface_aliases() {
    assert_eq!(parse_target("3000").expect("port"), Target::Port(3000));
    assert_eq!(
        parse_target("localhost:8080").expect("localhost"),
        Target::HostPort("localhost".to_owned(), 8080)
    );
    assert_eq!(
        parse_target("127.0.0.1:9000").expect("ip"),
        Target::HostPort("127.0.0.1".to_owned(), 9000)
    );
    assert_eq!(
        parse_target("lan:443").expect("alias"),
        Target::Iface { alias: "lan".to_owned(), port: 443 }
    );
    for target in ["0", "localhost:0"] {
        let error = parse_target(target).expect_err("zero port rejected");
        assert!(error.to_string().contains("port must be non-zero"));
    }
    assert!(parse_target("missing-port").expect_err("invalid target").to_string().contains("PORT"));
    assert!(parse_target("localhost:not-a-port").is_err());
    for target in ["52731", "localhost:52731", "127.0.0.1:52731", "lan:52731"] {
        let error = parse_target(target).expect_err("management port rejected");
        assert!(error.to_string().contains("reserved"), "{target}: {error}");
    }
}

#[tokio::test]
async fn stable_provider_specs_generate_hosts_and_external_ports() {
    let mut config = ClientConfig::default();
    config.defaults.stable_worktree_urls = true;
    config.defaults.domain = Some("preview.example.com".to_owned());
    config.defaults.tailscale_https_port_range = HttpsPortRange { start: 22_000, end: 22_099 };

    let wormhole =
        build_specs(ServiceProto::Http, &TunnelOptions::default(), &config, Some("store-fix-cart"))
            .await
            .expect("wormhole");
    assert_eq!(wormhole[0].host.as_deref(), Some("store-fix-cart"));
    assert_eq!(wormhole[0].domain.as_deref(), Some("preview.example.com"));
    assert_eq!(wormhole[0].persist, Persistence::Persistent);

    let explicit_host =
        TunnelOptions { host: Some("manual".to_owned()), ..TunnelOptions::default() };
    let explicit_host =
        build_specs(ServiceProto::Http, &explicit_host, &config, Some("store-fix-cart"))
            .await
            .expect("explicit host");
    assert_eq!(explicit_host[0].host.as_deref(), Some("manual"));
    assert_eq!(explicit_host[0].persist, Persistence::Temporary);

    config.defaults.local_tld = "localhost".to_owned();
    let local_options =
        TunnelOptions { endpoint: vec!["local".to_owned()], ..TunnelOptions::default() };
    let local = build_specs(ServiceProto::Http, &local_options, &config, Some("store-fix-cart"))
        .await
        .expect("local");
    assert_eq!(local[0].host.as_deref(), Some("store-fix-cart.localhost"));
    assert_eq!(local[0].persist, Persistence::Temporary);

    let custom_local = TunnelOptions {
        endpoint: vec!["local".to_owned()],
        tld: Some("test".to_owned()),
        ..TunnelOptions::default()
    };
    let custom_local =
        build_specs(ServiceProto::Http, &custom_local, &config, Some("store-fix-cart"))
            .await
            .expect("custom local TLD");
    assert_eq!(custom_local[0].host.as_deref(), Some("store-fix-cart.test"));

    let tailscale =
        TunnelOptions { endpoint: vec!["tailscale".to_owned()], ..TunnelOptions::default() };
    let first = build_specs(ServiceProto::Http, &tailscale, &config, Some("store-fix-cart"))
        .await
        .expect("tailscale");
    let second = build_specs(ServiceProto::Http, &tailscale, &config, Some("store-fix-cart"))
        .await
        .expect("stable tailscale");
    assert_eq!(first[0].public_port, second[0].public_port);
    assert!((22_000..=22_099).contains(&first[0].public_port.expect("generated port")));
    let other = build_specs(ServiceProto::Http, &tailscale, &config, Some("store-fix-payment"))
        .await
        .expect("other worktree");
    assert_ne!(first[0].public_port, other[0].public_port);

    let funnel =
        TunnelOptions { endpoint: vec!["tailscale:funnel".to_owned()], ..TunnelOptions::default() };
    let funnel = build_specs(ServiceProto::Http, &funnel, &config, Some("store-fix-cart"))
        .await
        .expect("funnel");
    assert!([443, 8443, 10_000].contains(&funnel[0].public_port.expect("funnel port")));

    let cloudflare_options =
        TunnelOptions { endpoint: vec!["cloudflare:named".to_owned()], ..TunnelOptions::default() };
    let cloudflare =
        build_specs(ServiceProto::Http, &cloudflare_options, &config, Some("store-fix-cart"))
            .await
            .expect("cloudflare");
    assert_eq!(cloudflare[0].host.as_deref(), Some("store-fix-cart.preview.example.com"));
    assert_eq!(cloudflare[0].persist, Persistence::Persistent);
    let other =
        build_specs(ServiceProto::Http, &cloudflare_options, &config, Some("store-fix-payment"))
            .await
            .expect("other Cloudflare worktree");
    assert_ne!(cloudflare[0].host, other[0].host);

    let explicit = TunnelOptions {
        endpoint: vec!["tailscale".to_owned()],
        public_port: Some(24_443),
        ..TunnelOptions::default()
    };
    let explicit = build_specs(ServiceProto::Http, &explicit, &config, Some("store-fix-cart"))
        .await
        .expect("explicit port");
    assert_eq!(explicit[0].public_port, Some(24_443));
}

#[tokio::test]
async fn local_tld_override_validates_scope_and_dns_rules() {
    let config = ClientConfig::default();
    let invalid = TunnelOptions {
        endpoint: vec!["local".to_owned()],
        tld: Some("Invalid TLD".to_owned()),
        ..TunnelOptions::default()
    };
    assert!(build_specs(ServiceProto::Http, &invalid, &config, Some("app")).await.is_err());

    let unrelated = TunnelOptions { tld: Some("test".to_owned()), ..TunnelOptions::default() };
    assert!(build_specs(ServiceProto::Http, &unrelated, &config, Some("app")).await.is_err());
}

#[tokio::test]
async fn stable_provider_specs_require_domain_and_preserve_opt_out() {
    let options =
        TunnelOptions { endpoint: vec!["cloudflare:named".to_owned()], ..TunnelOptions::default() };
    let mut stable = ClientConfig::default();
    stable.defaults.stable_worktree_urls = true;
    assert!(
        build_specs(ServiceProto::Http, &options, &stable, Some("store-main"))
            .await
            .expect_err("domain required")
            .to_string()
            .contains("WORMHOLE_DOMAIN")
    );
    let invalid = TunnelOptions {
        endpoint: vec!["cloudflare:named".to_owned()],
        host: Some("Invalid Host".to_owned()),
        ..TunnelOptions::default()
    };
    assert!(
        build_specs(ServiceProto::Http, &invalid, &stable, Some("store-main"))
            .await
            .expect_err("invalid host")
            .to_string()
            .contains("lowercase DNS")
    );

    let mut disabled = ClientConfig::default();
    disabled.defaults.stable_worktree_urls = false;
    let tailscale =
        TunnelOptions { endpoint: vec!["tailscale".to_owned()], ..TunnelOptions::default() };
    let unchanged = build_specs(ServiceProto::Http, &tailscale, &disabled, Some("store-main"))
        .await
        .expect("opt out");
    assert_eq!(unchanged[0].public_port, None);
}

#[tokio::test]
async fn specs_apply_driver_qualifiers_auth_capture_buffer_and_retry() {
    let mut config = ClientConfig::default();
    config.defaults.inspect = true;
    config.defaults.drivers = vec!["cloudflare:named".to_owned(), "wormhole:edge".to_owned()];
    let options = TunnelOptions {
        persist: true,
        host: Some("web".to_owned()),
        public_port: Some(8443),
        buffer: Some(12),
        retry: Some("attempts=4,backoff=25ms,max_backoff=2s,on=connect-error+5xx,max_body=2MiB,total_deadline=5s".to_owned()),
        auth: vec!["basic:user:pass".to_owned(), "bearer:secret".to_owned(), "links".to_owned()],
        capture: crate::cli::CaptureOptions {
            include_assets: true,
            capture_body_max: 4096,
            ..crate::cli::CaptureOptions::default()
        },
        ..TunnelOptions::default()
    };

    let specs = build_specs(ServiceProto::Http, &options, &config, None).await.expect("specs");
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].driver, "cloudflare");
    assert_eq!(specs[0].qualifier.as_deref(), Some("named"));
    assert_eq!(specs[1].remote.as_deref(), Some("edge"));
    assert!(specs.iter().all(|spec| spec.persist == Persistence::Persistent));
    assert!(specs.iter().all(|spec| spec.inspect && spec.inspect_assets));
    let retry = specs[0].retry.as_ref().expect("retry");
    assert_eq!((retry.max_attempts, retry.initial_delay_ms, retry.max_delay_ms), (4, 25, 2_000));
    assert!(retry.retry_connect && retry.retry_5xx);
    assert_eq!((retry.max_body_bytes, retry.total_deadline_ms), (2 * 1024 * 1024, 5_000));
    let auth = specs[0].auth.as_ref().expect("auth");
    assert_eq!(auth.basic.as_deref(), Some("user:pass"));
    assert_eq!(auth.bearer.as_deref(), Some("secret"));
    assert!(auth.link_key.is_some());
    assert_eq!(specs[0].buffer.as_ref().expect("buffer").max_requests, 12);
}

#[tokio::test]
async fn spec_validation_rejects_ambiguous_or_incomplete_policies() {
    let mut config = ClientConfig::default();
    config.defaults.drivers.clear();
    assert!(
        build_specs(ServiceProto::Tcp, &TunnelOptions::default(), &config, None)
            .await
            .expect_err("drivers required")
            .to_string()
            .contains("no endpoint drivers")
    );

    for auth in ["basic:missing-password", "bearer:", "unknown", "bearer:a"] {
        let values = if auth == "bearer:a" {
            vec![auth.to_owned(), "bearer:b".to_owned()]
        } else {
            vec![auth.to_owned()]
        };
        let options = TunnelOptions {
            endpoint: vec!["mock".to_owned()],
            auth: values,
            ..TunnelOptions::default()
        };
        assert!(build_specs(ServiceProto::Http, &options, &config, None).await.is_err(), "{auth}");
    }
    for retry in [
        "backoff=1s",
        "attempts=2",
        "attempts=x,backoff=1s",
        "attempts=2,backoff=1s,unknown=x",
        "not-an-assignment",
    ] {
        let options = TunnelOptions {
            endpoint: vec!["mock".to_owned()],
            retry: Some(retry.to_owned()),
            ..TunnelOptions::default()
        };
        assert!(build_specs(ServiceProto::Http, &options, &config, None).await.is_err(), "{retry}");
    }
}

#[tokio::test]
async fn auth_file_and_remote_override_are_applied() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("auth");
    tokio::fs::write(&path, " bearer:file-secret \n").await.expect("auth file");
    let config = ClientConfig::default();
    let options = TunnelOptions {
        endpoint: vec!["ignored:qualifier".to_owned()],
        remote: Some("other".to_owned()),
        auth_file: Some(path),
        ..TunnelOptions::default()
    };

    let specs = build_specs(ServiceProto::Tcp, &options, &config, None).await.expect("spec");
    assert_eq!(specs[0].driver, "wormhole");
    assert_eq!(specs[0].remote.as_deref(), Some("other"));
    assert_eq!(specs[0].auth.as_ref().and_then(|auth| auth.bearer.as_deref()), Some("file-secret"));
    assert!(!specs[0].inspect);
}

#[tokio::test]
async fn interface_target_resolves_configured_alias() {
    let mut config = ClientConfig::default();
    config.aliases.insert("loop".to_owned(), "127.0.0.1".to_owned());
    let resolved = resolve_target(Target::Iface { alias: "loop".to_owned(), port: 8080 }, &config)
        .await
        .expect("resolved alias");
    assert_eq!(resolved, Target::HostPort("127.0.0.1".to_owned(), 8080));
    assert_eq!(
        resolve_target(Target::Port(80), &config).await.expect("unchanged"),
        Target::Port(80)
    );
}

#[tokio::test]
async fn foreground_manager_exposes_persistent_mock_and_confirms_handoff() {
    let config = ClientConfig::default();
    let options = TunnelOptions {
        endpoint: vec!["mock".to_owned()],
        persist: true,
        host: Some("foreground".to_owned()),
        ..TunnelOptions::default()
    };
    let specs = build_specs(ServiceProto::Http, &options, &config, None).await.expect("specs");
    let service = Service {
        name: "foreground".to_owned(),
        target: Target::Port(3000),
        proto: ServiceProto::Http,
    };
    let registry = DriverRegistry::new();
    registry.register(Arc::new(crate::mock_driver::MockDriver));

    let (manager, endpoints) =
        start_foreground_with_registry(service, specs, config, registry).await.expect("expose");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].status, EndpointStatus::Online);
    assert_eq!(endpoints[0].urls, ["https://foreground.mock.invalid"]);
    manager.shutdown_with_forget().await.expect("shutdown");
}

#[test]
fn endpoint_outcomes_preserve_denied_partial_and_total_failure() {
    assert!(endpoint_result(&[endpoint(EndpointStatus::Online)]).is_ok());
    let partial = endpoint_result(&[
        endpoint(EndpointStatus::Online),
        endpoint(EndpointStatus::Error("provider failed".to_owned())),
    ])
    .expect_err("partial");
    assert_eq!(partial.exit_code(), 6);
    let failed = endpoint_result(&[endpoint(EndpointStatus::Offline)]).expect_err("failed");
    assert_eq!(failed.exit_code(), 5);
    let denied = endpoint_result(&[endpoint(EndpointStatus::Error("Access DENIED".to_owned()))])
        .expect_err("denied");
    assert!(denied.to_string().contains("DENIED"));
}

fn endpoint(status: EndpointStatus) -> ActiveEndpoint {
    ActiveEndpoint {
        id: uuid::Uuid::now_v7(),
        service: "web".to_owned(),
        driver: "mock".to_owned(),
        urls: Vec::new(),
        hints: Vec::new(),
        warnings: Vec::new(),
        status,
        buffered_delivered: 0,
        buffered_pending: 0,
        buffered_failed: 0,
        since: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }
}
