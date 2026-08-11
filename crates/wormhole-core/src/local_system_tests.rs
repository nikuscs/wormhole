use std::sync::Mutex;

use camino::Utf8Path;

use super::{
    CommandOutput, CommandRunner, ELEVATION_MARKER, HOSTS_BEGIN, HOSTS_END, LocalPlatform,
    elevation_commands, elevation_enabled, forwarder_definition, hosts_install_command,
    managed_hosts, prepare_hosts_file, remove_elevation_marker, render_hosts, root_forwarder_path,
    trust_commands, trust_state, unelevation_commands, untrust_commands, verify_executable_source,
    write_elevation_marker,
};

#[derive(Default)]
struct FakeRunner {
    commands: Mutex<Vec<String>>,
}

impl CommandRunner for FakeRunner {
    fn run(&self, command: &super::CommandSpec) -> Result<CommandOutput, std::io::Error> {
        self.commands.lock().expect("commands").push(command.display());
        Ok(CommandOutput {
            success: true,
            stdout: "label: Wormhole Local CA".to_owned(),
            stderr: String::new(),
        })
    }
}

#[test]
fn hosts_block_render_parse_update_and_remove_round_trip() {
    let original = "127.0.0.1 localhost\n10.0.0.1 unrelated\n";
    let first = render_hosts(
        original,
        &["App.Test".to_owned(), "api.test".to_owned(), "app.test".to_owned()],
    );
    assert_eq!(managed_hosts(&first), ["api.test", "app.test"]);
    assert_eq!(first.matches(HOSTS_BEGIN).count(), 1);
    assert_eq!(first.matches(HOSTS_END).count(), 1);

    let updated = render_hosts(&first, &["web.test".to_owned()]);
    assert_eq!(managed_hosts(&updated), ["web.test"]);
    assert_eq!(updated.matches(HOSTS_BEGIN).count(), 1);

    let removed = render_hosts(&updated, &[]);
    assert_eq!(removed, original);

    let directory = tempfile::tempdir().expect("directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8 path").join("hosts");
    std::fs::write(&path, original).expect("hosts fixture");
    let prepared = prepare_hosts_file(&path, &["app.test".to_owned()]).expect("prepared hosts");
    assert_eq!(managed_hosts(&prepared), ["app.test"]);
}

#[test]
fn privileged_plans_are_explicit_and_execute_only_through_runner() {
    let ca = Utf8Path::new("/tmp/Wormhole CA.pem");
    let source = Utf8Path::new("/opt/wormhole source");
    let temporary = Utf8Path::new("/tmp/wormhole service");
    let runner = FakeRunner::default();
    let mut commands = trust_commands(LocalPlatform::MacOs, ca, true);
    commands.extend(untrust_commands(LocalPlatform::Linux, ca, true));
    commands.extend(elevation_commands(LocalPlatform::Linux, source, temporary));
    commands.extend(unelevation_commands(LocalPlatform::MacOs));
    commands.push(hosts_install_command(temporary, Utf8Path::new("/etc/hosts")));

    for command in &commands {
        runner.run(command).expect("fake command");
    }

    let executed = runner.commands.lock().expect("commands");
    assert_eq!(executed.len(), commands.len());
    assert!(executed[0].contains("sudo security add-trusted-cert"));
    assert!(executed[0].contains("'/tmp/Wormhole CA.pem'"));
    assert!(executed.iter().any(|command| command.contains("systemctl enable --now")));
    assert!(executed.iter().any(|command| {
        command.contains("'/opt/wormhole source'")
            && command.contains("/usr/local/lib/wormhole/wormhole-local-forwarder")
    }));
    assert!(executed.iter().any(|command| command.contains("launchctl bootout")));
    assert!(executed.last().expect("hosts command").contains("/etc/hosts"));
    drop(executed);
}

#[test]
fn trust_status_uses_injected_runner_without_system_mutation() {
    let runner = FakeRunner::default();
    let (trusted, detail) = trust_state(LocalPlatform::Linux, true, true, false, &runner);
    assert!(trusted);
    assert_eq!(detail, "trusted");
    assert_eq!(runner.commands.lock().expect("commands").len(), 1);

    let (trusted, detail) = trust_state(LocalPlatform::Linux, false, true, true, &runner);
    assert!(trusted);
    assert_eq!(detail, "installed anchor");
}

/// A certificate can sit in the keychain while nothing trusts it, which is how macOS reported
/// success for an authority that browsers still rejected.
#[test]
fn a_present_but_untrusted_certificate_is_not_reported_as_trusted() {
    let runner = SilentRunner;
    let (trusted, detail) = trust_state(LocalPlatform::MacOs, false, true, false, &runner);
    assert!(!trusted, "empty trust settings must not read as trusted");
    assert!(detail.contains("not trusted"), "{detail}");
}

#[test]
fn privileged_commands_keep_the_terminal_for_their_prompts() {
    let ca = camino::Utf8Path::new("/tmp/local-ca.pem");
    for command in trust_commands(LocalPlatform::MacOs, ca, false) {
        assert_eq!(command.program, "sudo");
        assert!(command.interactive, "sudo must be able to prompt: {}", command.display());
    }
    let check = super::trust_check_command(LocalPlatform::MacOs, false).expect("check command");
    assert!(!check.interactive, "read-only probes stay captured so output can be inspected");
}

/// Stands in for a system whose trust settings are empty.
struct SilentRunner;

impl CommandRunner for SilentRunner {
    fn run(&self, _command: &super::CommandSpec) -> Result<CommandOutput, std::io::Error> {
        Ok(CommandOutput { success: false, stdout: String::new(), stderr: String::new() })
    }
}

#[test]
fn linux_trust_falls_back_to_update_ca_trust() {
    let ca = Utf8Path::new("/tmp/local-ca.pem");
    let install = trust_commands(LocalPlatform::Linux, ca, false);
    let remove = untrust_commands(LocalPlatform::Linux, ca, false);

    assert!(install[0].display().contains("/etc/pki/ca-trust/source/anchors"));
    assert_eq!(install[1].display(), "sudo update-ca-trust extract");
    assert!(remove[0].display().contains("rm -f"));
    assert_eq!(remove[1].display(), "sudo update-ca-trust extract");
}

#[test]
fn forwarder_definitions_and_marker_are_deterministic() {
    let directory = tempfile::tempdir().expect("directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let plist = forwarder_definition(LocalPlatform::MacOs, 20_080, 20_443, 501, 20);
    let unit = forwarder_definition(LocalPlatform::Linux, 20_080, 20_443, 1000, 1000);

    assert!(plist.contains("/usr/local/libexec/wormhole-local-forwarder"));
    assert!(plist.contains("<key>UserName</key><string>root</string>"));
    assert!(plist.contains("<string>--drop-uid</string><string>501</string>"));
    assert!(unit.contains("/usr/local/lib/wormhole/wormhole-local-forwarder"));
    assert!(unit.contains("User=root\nGroup=root"));
    assert!(unit.contains("--clear-target=20080 --tls-target=20443"));
    assert!(unit.contains("--drop-uid=1000 --drop-gid=1000"));
    assert_eq!(
        root_forwarder_path(LocalPlatform::MacOs),
        Utf8Path::new("/usr/local/libexec/wormhole-local-forwarder")
    );
    assert!(!elevation_enabled(root));
    let marker = write_elevation_marker(root).expect("marker");
    assert_eq!(marker.file_name(), Some(ELEVATION_MARKER));
    assert!(elevation_enabled(root));
    remove_elevation_marker(root).expect("remove marker");
    assert!(!elevation_enabled(root));
}

#[test]
fn elevation_rejects_user_writable_executable_ancestry() {
    let directory = tempfile::tempdir().expect("directory");
    let executable = Utf8Path::from_path(directory.path()).expect("UTF-8 path").join("wormhole");
    std::fs::write(&executable, "fixture").expect("executable");

    let error = verify_executable_source(&executable).expect_err("writable source must fail");

    assert!(error.contains("refusing elevation"));
    assert!(error.contains("writable by a non-root user"));
}
