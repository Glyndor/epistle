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

/// A `podup` that records every argv it receives and does nothing else.
fn podup_stub(dir: &std::path::Path) -> String {
	let log = dir.join("podup.argv").display().to_string();
	let podup = dir.join("podup");
	std::fs::write(
		&podup,
		format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{log}\"\n"),
	)
	.expect("podup");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("mode");
	podup.display().to_string()
}

/// A configuration the certificates container can renew with: dns-01, a
/// `[dns]` provider, and the account key where `mail` reads it.
fn renewable_config(dir: &std::path::Path) -> (crate::config::Config, std::path::PathBuf) {
	let data_dir = dir.join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let token = dir.join("dns.token");
	std::fs::write(&token, "token").expect("token");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).expect("mode");
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\n\
		 challenge = 'dns-01'\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{}'\n",
		data_dir.display(),
		token.display()
	))
	.expect("config");
	crate::acme::renew::load_or_create_account_key(&data_dir).expect("account key");
	(config, data_dir)
}

/// The DNS credential the configuration names cannot be read: the switch
/// refuses before it touches the stack, because the container would exit at
/// start, after `mail` was stopped and the compose file rewritten.
#[test]
fn enable_refuses_a_dns_credential_it_cannot_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let token = dir.path().join("dns.token");
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\n\
		 challenge = 'dns-01'\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{}'\n",
		data_dir.display(),
		token.display()
	))
	.expect("config");
	let error = super::preflight(&config).expect_err("the credential is not there");
	assert!(error.contains("cannot be read"), "{error}");
	assert!(error.contains("cloudflare"), "{error}");
	// The stack is not touched: podup is never run.
	let compose = dir.path().join("compose.yaml");
	let before = Recorder::split_layout(false).compose;
	std::fs::write(&compose, &before).expect("compose");
	let podup = podup_stub(dir.path());
	let code = run(&config, &compose, &podup, true, true);
	assert_eq!(code, std::process::ExitCode::FAILURE);
	assert_eq!(std::fs::read_to_string(&compose).expect("compose"), before);
	assert!(
		!dir.path().join("podup.argv").exists(),
		"the stack must not be touched"
	);
	assert!(!crate::cli::init::host_secrets::acme_account_key(&data_dir).exists());
}

/// The control: a credential that can be read passes the pre-flight.
#[test]
fn a_dns_credential_that_can_be_read_passes_the_preflight() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (config, _) = renewable_config(dir.path());
	super::preflight(&config).expect("the credential is there");
}

/// An install with no account key anywhere: the switch refuses before it
/// touches the stack, because a key that is nowhere is a new account with
/// the authority.
#[test]
fn enable_refuses_when_there_is_no_account_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let token = dir.path().join("dns.token");
	std::fs::write(&token, "token").expect("token");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).expect("mode");
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\n\
		 challenge = 'dns-01'\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{}'\n",
		data_dir.display(),
		token.display()
	))
	.expect("config");
	let error = super::preflight(&config).expect_err("there is no account key");
	assert!(error.contains("there is no ACME account key"), "{error}");
	// The stack is not touched: podup is never run.
	let compose = dir.path().join("compose.yaml");
	let before = Recorder::split_layout(false).compose;
	std::fs::write(&compose, &before).expect("compose");
	let podup = podup_stub(dir.path());
	let code = run(&config, &compose, &podup, true, true);
	assert_eq!(code, std::process::ExitCode::FAILURE);
	assert_eq!(std::fs::read_to_string(&compose).expect("compose"), before);
	assert!(
		!dir.path().join("podup.argv").exists(),
		"the stack must not be touched"
	);
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
