use super::{
    configure_child, prepared_command, public_hostname,
    run_framework::{inject_framework_flags, public_url_environment},
    run_port::{reserve_all_families, reserve_app_port, reserve_generated_port_in, reserve_ipv6},
};
use crate::runtime::LOCAL_API_PORT;

#[test]
fn child_receives_public_url_environment_aliases() {
    let mut command = tokio::process::Command::new("true");
    command.env("APP_URL", "http://localhost:3000").env("VITE_APP_URL", "local");
    configure_child(&mut command, 4321, "https://app.example.com", &["VITE_APP_URL"]);

    for name in ["WORMHOLE_URL", "VITE_APP_URL", "APP_URL"] {
        let value = command
            .as_std()
            .get_envs()
            .find_map(|(key, value)| (key == name).then_some(value))
            .flatten()
            .expect("URL environment variable");
        assert_eq!(value, "https://app.example.com");
    }
    let vite_hosts = command
        .as_std()
        .get_envs()
        .find_map(|(key, value)| (key == "__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS").then_some(value))
        .flatten()
        .expect("Vite allowed hosts");
    assert!(vite_hosts.to_string_lossy().split(',').any(|host| host == "app.example.com"));
}

#[test]
fn frameworks_receive_only_their_public_url_conventions() {
    let cases = [
        ("vite", &[][..]),
        ("next", &["NEXT_PUBLIC_APP_URL", "NEXT_PUBLIC_SITE_URL"][..]),
        ("nuxt", &["NUXT_PUBLIC_APP_URL", "NUXT_PUBLIC_SITE_URL"][..]),
        ("astro", &["PUBLIC_APP_URL", "PUBLIC_SITE_URL"][..]),
        ("rsbuild", &["PUBLIC_APP_URL", "PUBLIC_SITE_URL"][..]),
        ("expo", &["EXPO_PUBLIC_APP_URL"][..]),
        ("cargo", &[][..]),
    ];
    for (framework, expected) in cases {
        let command = vec![framework.to_owned(), "dev".to_owned()];
        assert_eq!(public_url_environment(&command, std::path::Path::new(".")), expected);
    }
}

#[test]
fn sveltekit_vite_script_receives_public_url_conventions() {
    let directory = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        directory.path().join("package.json"),
        r#"{"scripts":{"dev":"vite dev"},"devDependencies":{"@sveltejs/kit":"latest"}}"#,
    )
    .expect("package JSON");
    let command = vec!["npm".to_owned(), "run".to_owned(), "dev".to_owned()];

    assert_eq!(
        public_url_environment(&command, directory.path()),
        ["PUBLIC_APP_URL", "PUBLIC_SITE_URL"]
    );
}

#[test]
fn public_hostname_accepts_absolute_http_urls_only() {
    assert_eq!(public_hostname("https://app.example.com/path"), Some("app.example.com".to_owned()));
    assert_eq!(public_hostname("/relative"), None);
    assert_eq!(public_hostname("not a URL"), None);
}

#[test]
fn framework_commands_receive_reserved_port_and_loopback_host() {
    let command =
        prepared_command(&["vite".to_owned(), "dev".to_owned()], 4321).expect("vite command");
    let args = command
        .as_std()
        .get_args()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(args, ["dev", "--port", "4321", "--strictPort", "--host", "127.0.0.1"]);
}

#[test]
fn explicit_framework_flags_are_never_overridden() {
    let command = prepared_command(
        &[
            "astro".to_owned(),
            "dev".to_owned(),
            "--port=3000".to_owned(),
            "--host".to_owned(),
            "0.0.0.0".to_owned(),
        ],
        4321,
    )
    .expect("astro command");
    let args = command
        .as_std()
        .get_args()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(args, ["dev", "--port=3000", "--host", "0.0.0.0"]);
}

#[test]
fn package_runners_and_package_scripts_receive_forwarded_flags() {
    let mut direct = vec!["npx".to_owned(), "--yes".to_owned(), "vite".to_owned()];
    inject_framework_flags(&mut direct, 4100, std::path::Path::new("."));
    assert_eq!(
        direct,
        ["npx", "--yes", "vite", "--port", "4100", "--strictPort", "--host", "127.0.0.1"]
    );

    let directory = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        directory.path().join("package.json"),
        r#"{"scripts":{"dev":"vite --host=0.0.0.0"}}"#,
    )
    .expect("package JSON");
    let mut script = vec!["npm".to_owned(), "run".to_owned(), "dev".to_owned()];
    inject_framework_flags(&mut script, 4200, directory.path());
    assert_eq!(script, ["npm", "run", "dev", "--", "--port", "4200", "--strictPort"]);
}

#[test]
fn turbo_workspace_script_overrides_hardcoded_next_port() {
    let directory = tempfile::tempdir().expect("tempdir");
    let website = directory.path().join("apps/website");
    std::fs::create_dir_all(&website).expect("workspace directory");
    std::fs::write(
        directory.path().join("package.json"),
        r#"{"scripts":{"dev:web":"turbo dev --filter=@app/website --log-prefix=none"},"workspaces":["apps/*"]}"#,
    )
    .expect("root package JSON");
    std::fs::write(
        website.join("package.json"),
        r#"{"name":"@app/website","scripts":{"dev":"next dev --port 4001"}}"#,
    )
    .expect("website package JSON");
    let mut arguments = vec!["bun".to_owned(), "run".to_owned(), "dev:web".to_owned()];

    inject_framework_flags(&mut arguments, 4300, directory.path());

    assert_eq!(arguments, ["bun", "run", "dev:web", "--", "--", "--port", "4300"]);
}

#[test]
fn unrelated_commands_are_unchanged() {
    let mut arguments = vec!["cargo".to_owned(), "run".to_owned()];
    inject_framework_flags(&mut arguments, 4321, std::path::Path::new("."));
    assert_eq!(arguments, ["cargo", "run"]);
}

#[test]
fn explicit_management_port_is_rejected() {
    let error = reserve_app_port(Some(LOCAL_API_PORT)).expect_err("management port rejected");
    assert!(error.to_string().contains("reserved"));
}

#[test]
fn concurrent_generated_ports_hold_distinct_process_leases() {
    let (first_port, first) = reserve_app_port(None).expect("first reservation");
    let (second_port, second) = reserve_app_port(None).expect("second reservation");
    assert_ne!(first_port, second_port);
    drop((first, second));
}

#[test]
fn generated_port_skips_ipv6_listener_and_selects_next_port() {
    let (occupied_port, occupied, next_port) = (50_000..59_999)
        .find_map(|port| {
            let occupied = reserve_ipv6(port).ok()?;
            let next = reserve_all_families(port + 1)?;
            drop(next);
            Some((port, occupied, port + 1))
        })
        .expect("consecutive IPv6-capable test ports");

    let (selected, reservation) =
        reserve_generated_port_in(occupied_port..=next_port).expect("next free port");

    assert_eq!(selected, next_port);
    drop((occupied, reservation));
}
