use clap::{CommandFactory as _, Parser as _};

use super::{Cli, Command, RelayCommand, RelayDeployCommand, RemoteCommand};

#[test]
fn top_level_help_is_stable() {
    let mut command = Cli::command();
    let help = command.render_long_help().to_string();
    insta::assert_snapshot!(help);
}

#[test]
fn every_subcommand_renders_help() {
    assert_help_recursive(Cli::command());
}

fn assert_help_recursive(mut command: clap::Command) {
    let name = command.get_name().to_owned();
    let help = command.render_long_help().to_string();
    assert!(!help.trim().is_empty(), "{name} help must not be empty");
    let mut index = 0;
    while let Some(subcommand) = command.get_subcommands().nth(index).cloned() {
        assert_help_recursive(subcommand);
        index += 1;
    }
}

#[test]
fn invite_enrollment_flag_parses_as_transient_remote_add_input() {
    let cli = Cli::try_parse_from([
        "wormhole",
        "remote",
        "add",
        "edge",
        "relay.example:443",
        "--invite",
        "whi_public_secret",
    ])
    .expect("remote invite must parse");
    assert!(matches!(
        cli.command,
        Command::Remote {
            command: RemoteCommand::Add { invite: Some(ref token), .. }
        } if token == "whi_public_secret"
    ));
}

#[test]
fn cloudflare_relay_deploy_parses_as_nested_command() {
    let cli = Cli::try_parse_from([
        "wormhole",
        "relay",
        "deploy",
        "cloudflare",
        "--domain",
        "example.com",
        "--relay-domain",
        "edge.example.com",
        "--worker-name",
        "edge-relay",
        "--manual-dns",
        "--dry-run",
    ])
    .expect("Cloudflare deploy command");
    assert!(matches!(
        cli.command,
        Command::Relay {
            command: RelayCommand::Deploy {
                provider: RelayDeployCommand::Cloudflare(ref args)
            }
        } if args.domain == "example.com"
            && args.relay_domain.as_deref() == Some("edge.example.com")
            && args.worker_name.as_deref() == Some("edge-relay")
            && args.manual_dns
            && args.dry_run
    ));
}

#[test]
fn stage_seven_commands_return_dedicated_variants() {
    for args in [
        ["wormhole", "inspect", "request-id"].as_slice(),
        ["wormhole", "requests", "--follow"].as_slice(),
        ["wormhole", "requests", "clear"].as_slice(),
        ["wormhole", "replay", "request-id"].as_slice(),
        ["wormhole", "share", "service"].as_slice(),
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
}
