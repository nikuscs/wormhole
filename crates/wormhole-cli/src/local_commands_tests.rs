use std::sync::Mutex;

use wormhole_core::local_system::{CommandOutput, CommandRunner, CommandSpec};

use super::{apply_commands, validate_hosts};

#[derive(Default)]
struct FakeRunner {
    commands: Mutex<Vec<String>>,
}

impl CommandRunner for FakeRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, std::io::Error> {
        self.commands.lock().expect("commands").push(command.display());
        Ok(CommandOutput { success: true, stdout: String::new(), stderr: String::new() })
    }
}

#[test]
fn confirmed_actions_run_in_order_and_report_both_output_contracts() {
    let runner = FakeRunner::default();
    let commands = vec![
        CommandSpec {
            program: "first".to_owned(),
            args: vec!["one".to_owned()],
            interactive: false,
        },
        CommandSpec {
            program: "second".to_owned(),
            args: vec!["two".to_owned()],
            interactive: false,
        },
    ];

    let result = apply_commands("fixture", commands, true, &runner).expect("action");

    assert_eq!(runner.commands.lock().expect("commands").as_slice(), ["first one", "second two"]);
    assert_eq!(crate::output::HumanRender::render(&result), "fixture: updated");
    let json = serde_json::to_value(&result).expect("JSON");
    assert_eq!(json["action"], "fixture");
    assert_eq!(json["commands"][0], "first one");
}

#[test]
fn custom_hosts_are_scoped_and_localhost_needs_no_block() {
    assert!(validate_hosts(&["app.test".to_owned()], "test").is_ok());
    assert!(validate_hosts(&["app.other".to_owned()], "test").is_err());
    assert!(validate_hosts(&["App.test".to_owned()], "test").is_err());
    assert!(validate_hosts(&["app.localhost".to_owned()], "localhost").is_err());
}
