use clap::Parser;

use super::super::MigrateCli;
use super::super::report::{bytes, plan};
use super::*;
use crate::cli::{Cli, Command};
use crate::migrate::imap::{FolderReport, Skipped};

fn imap_args(extra: &[&str]) -> Result<ImapArgs, clap::Error> {
	let mut argv = vec![
		"epistle",
		"migrate",
		"imap",
		"--account",
		"alice",
		"--host",
		"imap.example.org",
		"--user",
		"alice",
	];
	argv.extend(extra);
	Cli::try_parse_from(argv).map(|cli| match cli.command {
		Command::Migrate(super::super::MigrateArgs {
			action: MigrateCli::Imap(args),
			..
		}) => args,
		_ => unreachable!("parsed as migrate imap"),
	})
}

#[test]
fn tls_is_the_default_and_plaintext_needs_its_own_flag() {
	let tls = endpoint(&imap_args(&[]).expect("parse")).expect("endpoint");
	assert_eq!((tls.security, tls.port), (Security::Tls, 993));
	assert!(matches!(tls.verify, Verify::Roots { ref extra } if extra.is_empty()));
	let starttls = endpoint(&imap_args(&["--starttls"]).expect("parse")).expect("endpoint");
	assert_eq!(
		(starttls.security, starttls.port),
		(Security::StartTls, 143)
	);
	let plain = endpoint(&imap_args(&["--insecure-plaintext"]).expect("parse")).expect("endpoint");
	assert_eq!(plain.security, Security::Plaintext);
	let skip = endpoint(&imap_args(&["--insecure-skip-verify"]).expect("parse")).expect("endpoint");
	assert!(matches!(skip.verify, Verify::Skip));
	assert_eq!(skip.security, Security::Tls);
}

#[test]
fn contradictory_security_flags_are_usage_errors() {
	for flags in [
		&["--starttls", "--insecure-plaintext"][..],
		&["--insecure-plaintext", "--insecure-skip-verify"],
		&["--insecure-plaintext", "--ca-file", "/tmp/ca.pem"],
	] {
		let error = imap_args(flags).expect_err("conflict");
		assert_eq!(
			error.kind(),
			clap::error::ErrorKind::ArgumentConflict,
			"{flags:?}"
		);
	}
}

#[test]
fn the_password_is_not_an_argument() {
	let error = imap_args(&["--password", "hunter2"]).expect_err("no such flag");
	assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn a_ca_file_adds_trust_anchors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let pem = dir.path().join("ca.pem");
	let cert = rcgen::generate_simple_self_signed(vec!["imap.example.org".into()]).expect("cert");
	std::fs::write(&pem, cert.cert.pem()).expect("write");
	let args = imap_args(&["--ca-file", pem.to_str().expect("utf-8")]).expect("parse");
	let endpoint = endpoint(&args).expect("endpoint");
	assert!(matches!(endpoint.verify, Verify::Roots { ref extra } if extra.len() == 1));
	std::fs::write(&pem, "not a certificate").expect("write");
	assert!(endpoint_refused(&args));
}

fn endpoint_refused(args: &ImapArgs) -> bool {
	endpoint(args).err() == Some(ExitCode::from(crate::cli::exit::REFUSED))
}

#[test]
fn the_password_file_gives_its_first_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("pw");
	std::fs::write(
		&file,
		format!("{}\nignored\n", crate::test_fixtures::password()),
	)
	.expect("write");
	assert_eq!(
		password(Some(&file)).expect("read").as_str(),
		crate::test_fixtures::password()
	);
	std::fs::write(&file, "\n").expect("write");
	assert!(password(Some(&file)).is_err(), "an empty file is refused");
	assert!(password(Some(&dir.path().join("missing"))).is_err());
}

#[test]
fn sizes_read_like_sizes() {
	assert_eq!(bytes(512), "512 B");
	assert_eq!(bytes(4300), "4.2 KB");
	assert_eq!(bytes(92_400_000), "88.1 MB");
}

#[test]
fn the_dry_run_plan_lists_folders_and_skips() {
	let summary = Summary {
		dry_run: true,
		folders: vec![FolderReport {
			remote: "Sent Items".into(),
			local: "Sent".into(),
			messages: 12,
			planned_bytes: 2048,
			..FolderReport::default()
		}],
		skipped: vec![Skipped {
			folder: "[Gmail]/All Mail".into(),
			reason: "virtual".into(),
		}],
		copied: 0,
		bytes: 0,
	};
	let mut out = Vec::new();
	plan(&summary, &mut out);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(text.contains("Sent Items\tSent\t12\t2.0 KB"), "{text}");
	assert!(
		text.contains("[Gmail]/All Mail\t-\tskipped: virtual"),
		"{text}"
	);
}

#[test]
fn an_unknown_account_is_refused_before_any_connection() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	std::fs::write(
		&config_path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n",
			dir.path().display()
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let config = Config::load(&config_path).expect("load");
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		Default::default(),
		Vec::new(),
	)
	.expect("store");
	let alice = crate::directory_store::DynamicAccount::with_password(
		"alice".into(),
		vec!["alice@example.org".into()],
		crate::test_fixtures::password(),
		&crate::password::Policy::from_config(&config.auth),
		false,
	)
	.expect("account");
	store.add(alice).expect("add");
	assert_eq!(
		target(&config, "nobody").err(),
		Some(ExitCode::from(crate::cli::exit::REFUSED))
	);
	let alice = target(&config, "alice").expect("an existing account is accepted");
	assert_eq!(alice.account, "alice");
	assert_eq!(alice.quota, Some(crate::imap::session::DEFAULT_QUOTA_BYTES));
}

#[test]
fn the_recovery_body_limit_uses_the_configured_message_size() {
	let dir = tempfile::tempdir().unwrap();
	let mut config: Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n[[accounts]]\nname = \"alice\"\npassword_hash = \"unused\"\naddresses = [\"alice@example.org\"]\n",
		dir.path().display()
	)).unwrap();
	for (configured, expected) in [
		(None, 25 * 1024 * 1024),
		(Some(30 * 1024 * 1024), 30 * 1024 * 1024),
	] {
		config.max_message_size = configured;
		let local = target(&config, "alice").unwrap();
		assert_eq!(
			local.max_message_size, expected,
			"use the local configuration for recovery"
		);
	}
}
