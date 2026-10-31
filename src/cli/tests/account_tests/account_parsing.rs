//! Secondary suite for `epistle account …`: parser-surface tests,
//! legacy `account-add` / `account-remove` compatibility, and the
//! backwards-compatibility load of an `accounts.toml` written before
//! `quota_bytes` existed. Lives in a sibling so the primary suite
//! stays under the per-file line budget.

use super::*;

const DOMAIN: &str = "example.org";

#[test]
fn parse_quota_size_parser_accepts_whitespace_units() {
	// Trailing whitespace after the unit is allowed: a copy-paste from
	// a config file may include a stray space, and rejecting it serves
	// no one.
	assert_eq!(
		account::parse_quota_size("500M ").expect("trailing space"),
		Some(500 * 1024 * 1024)
	);
}

#[test]
fn accounts_toml_without_quota_bytes_loads_through_cli() {
	// An on-disk accounts.toml written before this branch existed
	// must keep loading: the field's #[serde(default)] keeps the
	// dynamic quota at None, and `account show` reports
	// "quota_bytes: server default". This is the CLI side of the
	// mutator test in src/directory_store/tests/account_mutators.rs.
	let dir = tempfile::tempdir().expect("tempdir");
	let text = r#"
[[accounts]]
name = "legacy"
addresses = ["legacy@example.org"]
password_hash = "stub"
"#;
	std::fs::write(dir.path().join("accounts.toml"), text).expect("write");

	let store = crate::directory_store::AccountStore::open(
		dir.path(),
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");

	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, "legacy", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("quota_bytes: server default"), "{text}");
	assert!(
		matches!(store.set_quota_bytes("legacy", None), Ok(None)),
		"a legacy account has no prior quota to report"
	);
}

#[test]
fn parses_legacy_account_add_and_remove() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account-add",
		"--config",
		"/etc/mail.toml",
		"--name",
		"bob",
		"--address",
		&format!("bob@{DOMAIN}"),
	])
	.expect("legacy account-add parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::AccountAdd { .. })
	));

	let cli = Cli::try_parse_from([
		"epistle",
		"account-remove",
		"--config",
		"/etc/mail.toml",
		"--name",
		"bob",
		"--queue",
		"discard",
	])
	.expect("legacy account-remove parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::AccountRemove { .. })
	));
}

#[test]
fn parses_every_account_subcommand() {
	let cases: &[&[&str]] = &[
		&["account", "password", "alice"],
		&["account", "disable", "alice"],
		&["account", "enable", "alice"],
		&[
			"account",
			"address",
			"add",
			"alice",
			&format!("alice2@{DOMAIN}"),
		],
		&[
			"account",
			"address",
			"remove",
			"alice",
			&format!("alice2@{DOMAIN}"),
		],
		&["account", "quota", "alice", "500M"],
		&["account", "protocols", "alice", "imap,api"],
		&["account", "show", "alice"],
	];
	for args in cases {
		let mut argv = vec!["epistle"];
		argv.extend_from_slice(args);
		let cli = Cli::try_parse_from(argv).unwrap_or_else(|error| {
			panic!("account subcommand {args:?} must parse: {error}");
		});
		assert!(
			matches!(cli.command, Command::Account { .. }),
			"account subcommand {args:?} must parse to Command::Account"
		);
	}
}
