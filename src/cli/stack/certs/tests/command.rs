//! `epistle stack certs`: what the operator types, and what it refuses
//! before it touches anything.

use super::*;
use clap::Parser;

fn parsed(args: &[&str]) -> crate::cli::stack::StackAction {
	let mut full = vec!["epistle", "stack"];
	full.extend_from_slice(args);
	match crate::cli::Cli::try_parse_from(full)
		.expect("parses")
		.command
	{
		crate::cli::Command::Stack { action, .. } => action.into(),
		other => panic!("not stack: {other:?}"),
	}
}

#[test]
fn enable_and_disable_parse_with_and_without_yes() {
	assert!(matches!(
		parsed(&["certs", "enable", "--yes"]),
		crate::cli::stack::StackAction::Certs {
			on: true,
			yes: true
		}
	));
	assert!(matches!(
		parsed(&["certs", "disable"]),
		crate::cli::stack::StackAction::Certs {
			on: false,
			yes: false
		}
	));
}

/// A configuration the certificates container cannot renew with is refused
/// by name, and the compose file is left exactly as it was.
#[test]
fn enable_refuses_http01_before_touching_the_stack() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\n",
		data_dir.display()
	))
	.expect("config");
	let compose = dir.path().join("compose.yaml");
	let before = Recorder::split_layout(false).compose;
	std::fs::write(&compose, &before).expect("compose");
	let code = run(&config, &compose, "false", true, true);
	assert_eq!(code, std::process::ExitCode::FAILURE);
	assert_eq!(std::fs::read_to_string(&compose).expect("compose"), before);
	assert!(!crate::cli::init::host_secrets::acme_account_key(&data_dir).exists());
}

/// `stack rollback` runs `disable` as the service account, without a
/// terminal: it has to pass `--yes` or the question stops it.
#[test]
fn rollback_turns_the_container_off_without_a_question() {
	let source = include_str!("../../rollback/run.rs");
	let call = source
		.split(".arg(\"certs\")")
		.nth(1)
		.and_then(|rest| rest.split(".status()").next())
		.expect("the certs call in rollback");
	assert!(call.contains(".arg(\"disable\")"), "{call}");
	assert!(call.contains(".arg(\"--yes\")"), "{call}");
}
