//! CLI argument parsing and command tests.

use super::*;
use clap::CommandFactory;
use std::io::Write;

#[test]
fn cli_definition_is_consistent() {
	Cli::command().debug_assert();
}

#[test]
fn parses_serve_command() {
	let cli = Cli::try_parse_from(["epistle", "serve", "--config", "/etc/mail.toml"])
		.expect("serve parses");
	assert!(matches!(cli.command, Command::Serve { .. }));
}

#[test]
fn serve_runs_everything_unless_a_role_is_named() {
	let role = |args: &[&str]| match Cli::try_parse_from(args).expect("serve parses").command {
		Command::Serve { role, .. } => role,
		other => panic!("not serve: {other:?}"),
	};
	assert_eq!(role(&["epistle", "serve"]), serve::ServeRole::All);
	assert_eq!(
		role(&["epistle", "serve", "--role", "mail"]),
		serve::ServeRole::Mail
	);
	assert_eq!(
		role(&["epistle", "serve", "--role", "certs"]),
		serve::ServeRole::Certs
	);
	assert!(Cli::try_parse_from(["epistle", "serve", "--role", "dkim"]).is_err());
}

#[test]
fn parses_config_check_command() {
	let cli = Cli::try_parse_from(["epistle", "config-check", "--config", "/etc/mail.toml"])
		.expect("config-check parses");
	assert!(matches!(cli.command, Command::ConfigCheck { .. }));
}

#[test]
fn rejects_missing_config_value() {
	assert!(Cli::try_parse_from(["epistle", "serve", "--config"]).is_err());
}

#[test]
fn rejects_unknown_subcommand() {
	assert!(Cli::try_parse_from(["epistle", "destroy"]).is_err());
}

#[test]
fn config_check_accepts_valid_file() {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(b"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
		.expect("write");
	let cli = Cli::try_parse_from([
		"epistle",
		"config-check",
		"--config",
		file.path().to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
}

#[test]
fn config_check_rejects_invalid_file() {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(b"hostname = \"localhost\"\ndata_dir = \"/var/lib/mail\"\n")
		.expect("write");
	let cli = Cli::try_parse_from([
		"epistle",
		"config-check",
		"--config",
		file.path().to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::FAILURE);
}

#[test]
fn dkim_keygen_writes_key_and_refuses_overwrite() {
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("dkim.pem");
	let cli = Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--out",
		out.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
	let pem = std::fs::read_to_string(&out).expect("key written");
	assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

	let cli = Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--out",
		out.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::FAILURE);
}

#[cfg(unix)]
#[test]
fn dkim_keygen_sets_owner_only_permissions() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let out = dir.path().join("dkim.pem");
	let cli = Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--out",
		out.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
	let mode = std::fs::metadata(&out)
		.expect("metadata")
		.permissions()
		.mode();
	assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn serve_fails_on_missing_config() {
	let cli = Cli::try_parse_from(["epistle", "serve", "--config", "/nonexistent/mail.toml"])
		.expect("parses");
	assert_eq!(cli.run(), ExitCode::FAILURE);
}

#[test]
fn parses_export_command() {
	let cli = Cli::try_parse_from([
		"epistle",
		"export",
		"--config",
		"/etc/mail.toml",
		"--account",
		"alice",
	])
	.expect("export parses");
	assert!(matches!(cli.command, Command::Export { .. }));
}

#[test]
fn export_writes_mbox_for_account() {
	let mut buf = Vec::new();
	export::write_entry(&mut buf, "INBOX", b"Subject: hi\r\n\r\nFrom the desk\r\n")
		.expect("write entry");
	let text = String::from_utf8(buf).expect("utf8");
	assert!(text.starts_with("From MAILER-DAEMON@localhost"), "{text}");
	assert!(text.contains("X-Mailbox: INBOX"), "{text}");
	assert!(text.contains(">From the desk"), "{text}");
}

#[test]
fn export_run_streams_account_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let new = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new).expect("mkdir");
	std::fs::write(
		new.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"Subject: one\r\n\r\nbody\r\n",
	)
	.expect("write");
	let mut out = Vec::new();
	assert_eq!(
		export::run(
			dir.path(),
			"alice",
			&crate::storage::MessageCrypto::disabled(),
			&mut out
		),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.starts_with("From MAILER-DAEMON@localhost"), "{text}");
	assert!(text.contains("Subject: one"), "{text}");

	let mut empty = Vec::new();
	assert_eq!(
		export::run(
			dir.path(),
			"nobody",
			&crate::storage::MessageCrypto::disabled(),
			&mut empty
		),
		ExitCode::SUCCESS
	);
	assert!(empty.is_empty());

	struct FailWriter;
	impl std::io::Write for FailWriter {
		fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
			Err(std::io::Error::other("boom"))
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Err(std::io::Error::other("boom"))
		}
	}
	assert_eq!(
		export::run(
			dir.path(),
			"alice",
			&crate::storage::MessageCrypto::disabled(),
			&mut FailWriter
		),
		ExitCode::FAILURE
	);
}
