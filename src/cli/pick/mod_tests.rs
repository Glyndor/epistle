//! A command missing its account, alias or domain, completed from a list on
//! a terminal and refused as before without one.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::Command;
use crate::cli::prompt::script::scripted;

/// A config with two static accounts, two aliases and two domains.
fn config(dir: &std::path::Path) -> String {
	let path = dir.join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\", \"example.net\"]\n\
			 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\n\
			 [[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n\
			 [[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n",
			dir
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path.to_string_lossy().into_owned()
}

fn args(argv: &[&str]) -> Vec<OsString> {
	argv.iter().map(OsString::from).collect()
}

#[test]
fn on_a_terminal_the_missing_account_is_picked_and_the_command_parses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let argv = args(&["epistle", "account", "show", "--config", &config]);
	let run = scripted(true, None, "2\n", || complete(&argv));
	let completed = run.value.expect("completed");
	assert_eq!(
		completed.last().map(OsString::as_os_str),
		Some("bob".as_ref())
	);
	assert!(
		run.stderr
			.contains("Pick an account:\n  1) alice\n  2) bob\n"),
		"{}",
		run.stderr
	);
	let cli = Cli::try_parse_from(&completed).expect("parses");
	assert!(matches!(
		cli.command,
		Command::Account { action: crate::cli::account::Subcommand::Show { ref name, .. }, .. } if name == "bob"
	));
}

#[test]
fn aliases_and_domains_come_from_the_configuration() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let argv = args(&["epistle", "alias", "--config", &config, "disable"]);
	let run = scripted(true, None, "1\n", || complete(&argv));
	assert_eq!(
		run.value
			.expect("completed")
			.last()
			.map(OsString::as_os_str),
		Some("team@example.org".as_ref())
	);
	let argv = args(&["epistle", "domain", "--config", &config, "show"]);
	let run = scripted(true, None, "example.net\n", || complete(&argv));
	assert_eq!(
		run.value
			.expect("completed")
			.last()
			.map(OsString::as_os_str),
		Some("example.net".as_ref())
	);
}

#[test]
fn without_a_terminal_nothing_is_asked_and_the_usage_error_stays() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let argv = args(&["epistle", "account", "show", "--config", &config]);
	let run = scripted(false, None, "1\n", || complete(&argv));
	assert!(run.value.is_none());
	assert_eq!(run.stderr, "");
	assert_eq!(run.unread, 2, "nothing was read");
}

#[test]
fn a_cancelled_pick_or_an_unreadable_config_keeps_the_usage_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let argv = args(&["epistle", "account", "show", "--config", &config]);
	assert!(
		scripted(true, None, "\n", || complete(&argv))
			.value
			.is_none()
	);
	let argv = args(&[
		"epistle",
		"account",
		"show",
		"--config",
		"/nonexistent/mail.toml",
	]);
	let run = scripted(true, None, "1\n", || complete(&argv));
	assert!(run.value.is_none());
	assert_eq!(run.unread, 2, "nothing was asked");
}

#[test]
fn an_app_password_revoke_picks_the_account_then_its_label() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let parsed = crate::config::Config::load(std::path::Path::new(&config)).expect("config");
	let mut store =
		crate::directory_store::AppPasswordStore::open(&parsed.data_dir).expect("store");
	store
		.add(
			"bob",
			crate::directory_store::AppPassword {
				label: "phone".into(),
				hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".into(),
				expires_at: None,
				ip_cidr: None,
			},
		)
		.expect("add");
	let argv = args(&["epistle", "app-password", "--config", &config, "revoke"]);
	let run = scripted(true, None, "2\n1\n", || complete(&argv));
	let completed = run.value.expect("completed");
	let tail: Vec<_> = completed.iter().rev().take(2).rev().cloned().collect();
	assert_eq!(tail, args(&["bob", "phone"]), "{}", run.stderr);
	assert!(
		run.stderr.contains("Pick an app password of bob:"),
		"{}",
		run.stderr
	);
}
