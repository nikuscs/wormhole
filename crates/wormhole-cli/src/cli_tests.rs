use clap::{CommandFactory as _, Parser as _};

use super::Cli;

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
fn stage_seven_commands_return_dedicated_variants() {
    for args in [
        ["wormhole", "inspect"].as_slice(),
        ["wormhole", "replay", "request-id"].as_slice(),
        ["wormhole", "share", "service"].as_slice(),
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
}
