use std::path::{Path, PathBuf};

use clap::Parser;

use super::super::super::{MigrateArgs, MigrateCli};
use super::*;
use crate::cli::{Cli, Command};

fn epistle(dir: &Path) -> PathBuf {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data");
	let file = dir.join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.new.example\"\ndata_dir = \"{}\"\ndomains = []\n",
			data.display()
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	file
}

fn parse(args: &[&str]) -> Result<(MigrateCli, PathBuf), clap::Error> {
	let mut argv = vec!["epistle", "migrate"];
	argv.extend(args);
	Cli::try_parse_from(argv).map(|cli| match cli.command {
		Command::Migrate(MigrateArgs { action, config }) => (action, config),
		_ => unreachable!("parsed as migrate"),
	})
}

fn import_args(action: MigrateCli) -> (PathBuf, ImportArgs) {
	match action {
		MigrateCli::Mox { from, import } | MigrateCli::Stalwart { from, import } => (from, import),
		MigrateCli::Imap(_) => unreachable!("an import"),
	}
}

#[test]
fn a_password_choice_is_required_unless_dry_run() {
	let error = parse(&["mox", "--from", "/etc/mox"]).expect_err("needs a choice");
	assert_eq!(
		error.kind(),
		clap::error::ErrorKind::MissingRequiredArgument
	);
	assert!(parse(&["mox", "--from", "/etc/mox", "--dry-run"]).is_ok());
	assert!(parse(&["mox", "--from", "/etc/mox", "--password-reset"]).is_ok());
	let error = parse(&[
		"mox",
		"--from",
		"/etc/mox",
		"--password-reset",
		"--passwords-out",
		"/root/pw",
	])
	.expect_err("one choice");
	assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn dry_run_prints_the_plan_writes_nothing_and_shows_no_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = dir.path().join("mox");
	std::fs::create_dir_all(&source).expect("mox dir");
	let written = crate::migrate::mox::fixture::write(&source);
	let before = std::fs::read(&config).expect("read");
	let (action, _) = parse(&[
		"mox",
		"--from",
		source.to_str().expect("utf-8"),
		"--dry-run",
	])
	.expect("parse");
	let (from, args) = import_args(action);
	let mut out = Vec::new();
	let (code, changed) = import(
		&config,
		crate::migrate::mox::read(&from).map_err(|e| e.to_string()),
		&args,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!changed);
	assert_eq!(std::fs::read(&config).expect("read"), before);
	assert!(!dir.path().join("data/accounts.toml").exists());
	let text = String::from_utf8(out).expect("utf-8");
	assert!(text.contains("accounts would add: alice, bob"), "{text}");
	assert!(
		text.contains("dkim key: example.com selector 2024a (ed25519)"),
		"{text}"
	);
	assert!(text.contains("to do by hand:"), "{text}");
	for pem in [&written.ed25519, &written.rsa] {
		let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
		assert!(!text.contains(&body[..40]), "key material printed");
	}
}

#[test]
fn apply_with_a_password_file_and_json() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let source = dir.path().join("mox");
	std::fs::create_dir_all(&source).expect("mox dir");
	crate::migrate::mox::fixture::write(&source);
	let passwords = dir.path().join("passwords");
	let (action, _) = parse(&[
		"mox",
		"--from",
		source.to_str().expect("utf-8"),
		"--passwords-out",
		passwords.to_str().expect("utf-8"),
		"--json",
	])
	.expect("parse");
	let (from, args) = import_args(action);
	let mut out = Vec::new();
	let (code, changed) = import(
		&config,
		crate::migrate::mox::read(&from).map_err(|e| e.to_string()),
		&args,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(changed);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(
		value["changes"]["accounts_added"],
		serde_json::json!(["alice", "bob"])
	);
	let shown = String::from_utf8_lossy(&out);
	let secrets = std::fs::read_to_string(&passwords).expect("passwords");
	assert_eq!(secrets.lines().count(), 2);
	for line in secrets.lines() {
		let (_, secret) = line.split_once('\t').expect("tab");
		assert!(
			!shown.contains(secret),
			"a temporary password reached stdout"
		);
	}
	assert!(!shown.contains("PRIVATE KEY"));
	// A second run refuses: everything exists now.
	let (code, changed) = import(
		&config,
		crate::migrate::mox::read(&from).map_err(|e| e.to_string()),
		&args,
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!changed);
}

#[test]
fn stalwart_json_and_apply_with_a_password_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let (file, _) = crate::migrate::stalwart::fixture::write(dir.path());
	let passwords = dir.path().join("passwords");
	let (action, _) = parse(&[
		"stalwart",
		"--from",
		file.to_str().expect("utf-8"),
		"--passwords-out",
		passwords.to_str().expect("utf-8"),
		"--json",
	])
	.expect("parse");
	let (from, args) = import_args(action);
	let mut out = Vec::new();
	let (code, changed) = import(
		&config,
		crate::migrate::stalwart::read(&from).map_err(|e| e.to_string()),
		&args,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(changed);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(
		value["changes"]["accounts_added"],
		serde_json::json!(["john", "jane"])
	);
	let shown = String::from_utf8_lossy(&out);
	let secrets = std::fs::read_to_string(&passwords).expect("passwords");
	for line in secrets.lines() {
		let (_, secret) = line.split_once('\t').expect("tab");
		assert!(
			!shown.contains(secret),
			"a temporary password reached stdout"
		);
	}
	assert!(!shown.contains("PRIVATE KEY"));
}

#[test]
fn an_unreadable_source_is_a_refusal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path());
	let (action, _) = parse(&["mox", "--from", "/nonexistent", "--dry-run"]).expect("parse");
	let (from, args) = import_args(action);
	let (code, changed) = import(
		&config,
		crate::migrate::mox::read(&from).map_err(|e| e.to_string()),
		&args,
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED));
	assert!(!changed);
}
