use std::sync::Mutex;

use camino::Utf8Path;

use super::{
    CommandOutput, CommandRunner, ELEVATION_MARKER, HOSTS_BEGIN, HOSTS_END, LocalPlatform,
    elevation_commands, elevation_enabled, forwarder_definition, hosts_install_command,
    managed_hosts, prepare_hosts_file, render_hosts, trust_commands, trust_state, untrust_commands,
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
    let temporary = Utf8Path::new("/tmp/wormhole service");
    let runner = FakeRunner::default();
    let mut commands = trust_commands(LocalPlatform::MacOs, ca, true);
    commands.extend(untrust_commands(LocalPlatform::Linux, ca, true));
    commands.extend(elevation_commands(LocalPlatform::Linux, temporary));
    commands.push(hosts_install_command(temporary, Utf8Path::new("/etc/hosts")));

    for command in &commands {
        runner.run(command).expect("fake command");
    }

    let executed = runner.commands.lock().expect("commands");
    assert_eq!(executed.len(), commands.len());
    assert!(executed[0].contains("sudo security add-trusted-cert"));
    assert!(executed[0].contains("'/tmp/Wormhole CA.pem'"));
    assert!(executed.iter().any(|command| command.contains("systemctl enable --now")));
    assert!(executed.last().expect("hosts command").contains("/etc/hosts"));
    drop(executed);
}

#[test]
fn trust_status_uses_injected_runner_without_system_mutation() {
    let runner = FakeRunner::default();
    let (trusted, detail) = trust_state(LocalPlatform::Linux, true, true, false, &runner);
    assert!(trusted);
    assert_eq!(detail, "installed");
    assert_eq!(runner.commands.lock().expect("commands").len(), 1);

    let (trusted, detail) = trust_state(LocalPlatform::Linux, false, true, true, &runner);
    assert!(trusted);
    assert_eq!(detail, "installed anchor");
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
    let executable = Utf8Path::new("/opt/Wormhole & Co/wormhole");
    let plist = forwarder_definition(LocalPlatform::MacOs, executable, 20_080, 20_443);
    let unit = forwarder_definition(LocalPlatform::Linux, executable, 20_080, 20_443);

    assert!(plist.contains("/opt/Wormhole &amp; Co/wormhole"));
    assert!(plist.contains("<string>20080</string>"));
    assert!(unit.contains("--clear-target=20080 --tls-target=20443"));
    assert!(!elevation_enabled(root));
    let marker = write_elevation_marker(root).expect("marker");
    assert_eq!(marker.file_name(), Some(ELEVATION_MARKER));
    assert!(elevation_enabled(root));
}
