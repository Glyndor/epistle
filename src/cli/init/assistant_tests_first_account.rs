//! The first account in the wizard: asked after the domains, the password
//! typed twice with echo off on a terminal, and skipped with an empty line.

use super::super::detect::tests::Scripted;
use super::*;
use crate::cli::prompt::script::{Pty, scripted};

/// Manual-mode answers with `account` lines right after the domain list.
fn input(account: &str) -> String {
	let mut text = String::from("manual\nmail.example.org\nexample.org\nexample.net\n\n");
	text.push_str(account);
	// Both address questions, the two paths, seven services and the image.
	text.push_str("\n\n/var/lib/epistle\n/etc/epistle/mail.toml\n");
	text.push_str(&"\n".repeat(8));
	text
}

fn drive(text: &str) -> (Result<Filled, ()>, String) {
	let mut reader = std::io::BufReader::new(text.as_bytes());
	let mut out = Vec::new();
	let result = run(&mut reader, &mut out, &Scripted::found(None, None));
	(result, String::from_utf8(out).expect("utf-8"))
}

#[test]
fn on_a_terminal_the_password_is_typed_twice_with_echo_off() {
	let pty = Pty::open();
	let text = input("alice@example.org\nAlice Liddell\nZq8!vT3#mL0@pW6$\nZq8!vT3#mL0@pW6$\n\n");
	let run = scripted(true, Some(pty.slave), "", || drive(&text));
	let (result, printed) = run.value;
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}{}", run.stderr));
	let first = filled
		.answers
		.first_account
		.as_ref()
		.expect("first account");
	assert_eq!(first.address, "alice@example.org");
	assert_eq!(first.display_name.as_deref(), Some("Alice Liddell"));
	assert!(first.role_aliases, "the role aliases default to yes");
	assert_eq!(
		filled.first_password.as_ref().map(Password::expose),
		Some("Zq8!vT3#mL0@pW6$")
	);
	assert!(
		run.stderr
			.contains("Password for \"alice\": \nRepeat password: \n"),
		"{}",
		run.stderr
	);
	assert!(
		!printed.contains("Zq8!"),
		"the password is never echoed: {printed}"
	);
	assert!(pty.echo_on(), "echo is back after the wizard");
}

#[test]
fn a_mismatch_or_a_weak_password_is_asked_again() {
	let pty = Pty::open();
	let text = input(
		"alice@example.org\n\nZq8!vT3#mL0@pW6$\nsomething else\nshort\nshort\nZq8!vT3#mL0@pW6$\nZq8!vT3#mL0@pW6$\nn\n",
	);
	let run = scripted(true, Some(pty.slave), "", || drive(&text));
	let (result, printed) = run.value;
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}{}", run.stderr));
	assert!(
		run.stderr.contains("passwords do not match"),
		"{}",
		run.stderr
	);
	assert_eq!(
		filled.answers.first_account.map(|a| a.role_aliases),
		Some(false)
	);
	assert!(filled.first_password.is_some());
}

#[test]
fn an_address_outside_the_domains_is_asked_again() {
	let text = input("alice@elsewhere.example\nalice@example.net\n\nZq8!vT3#mL0@pW6$\n\n");
	let run = scripted(false, None, "", || drive(&text));
	let (result, printed) = run.value;
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}{}", run.stderr));
	assert!(
		printed.contains("not one of the configured domains"),
		"{printed}"
	);
	assert_eq!(
		filled.answers.first_account.map(|a| a.address).as_deref(),
		Some("alice@example.net")
	);
}

#[test]
fn an_empty_address_skips_the_first_account() {
	let (result, printed) = drive(&input("\n"));
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}"));
	assert!(filled.answers.first_account.is_none());
	assert!(filled.first_password.is_none());
	assert!(
		printed.contains("first account address (empty to skip)> "),
		"{printed}"
	);
}

#[test]
fn the_wizard_says_which_account_name_the_address_gives() {
	let text = input("Torre.Control@example.org\n\nZq8!vT3#mL0@pW6$\n\n");
	let (result, printed) = drive(&text);
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}"));
	assert!(
		printed.contains(
			"the account name will be \"torre-control\" (dots become hyphens and capital letters become lowercase)"
		),
		"{printed}"
	);
	assert_eq!(
		filled.answers.first_account.map(|a| a.name()),
		Some("torre-control".to_string())
	);
	let (_, plain) = drive(&input("alice@example.org\n\nZq8!vT3#mL0@pW6$\n\n"));
	assert!(!plain.contains("the account name will be"), "{plain}");
}

#[test]
fn an_address_whose_name_is_taken_is_asked_again_once_the_paths_are_known() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = dir.path().join("etc").join("mail.toml");
	let data = dir.path().join("data");
	std::fs::create_dir_all(config.parent().expect("parent")).expect("mkdir");
	std::fs::write(
		&config,
		format!("hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n\n[[accounts]]\nname = \"torre-control\"\naddresses = [\"torre-control@example.org\"]\n", data.display()),
	)
	.expect("write config");
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	let mut text = String::from("manual\nmail.example.org\nexample.org\nexample.net\n\n");
	text.push_str("torre.control@example.org\n\nZq8!vT3#mL0@pW6$\n\n");
	text.push_str(&format!("\n\n{}\n{}\n", data.display(), config.display()));
	text.push_str("alice@example.org\n\nZq8!vT3#mL0@pW6$\n\n");
	text.push_str(&"\n".repeat(8));
	let (result, printed) = drive(&text);
	let filled = result.unwrap_or_else(|()| panic!("gave up: {printed}"));
	assert!(
		printed.contains("same name") && printed.contains("try again"),
		"{printed}"
	);
	assert_eq!(
		filled.answers.first_account.map(|a| a.address),
		Some("alice@example.org".to_string())
	);
}
