//! CLI tests for the `epistle account-remove` command.
//!
//! Lives in a sibling test module so the parent `cli_tests_b.rs` file
//! stays under the per-file line budget. The whole suite here goes
//! through `Cli::try_parse_from` and `accounts::remove` (the CLI
//! entry point itself, not through `Cli::run`); the dispatch path is
//! covered by `cli_tests_b::account_create_delete_and_password_flow`
//! and `cli_tests_b::accounts_dispatch_succeeds`.

use super::*;
use crate::cli::Command;
use crate::cli::tests_b::config_at;
use crate::directory_store::removal::QueuePolicy;

/// `epistle account-remove --config F --name N --queue discard|drain`
/// parses cleanly. The required `--queue` flag exists, the policy enum
/// is wired, and an unknown policy is rejected at the parser layer so
/// the typo never reaches the removal flow.
#[test]
fn parses_account_remove_with_each_queue_policy() {
	for (flag, expected) in [
		("discard", QueuePolicy::Discard),
		("drain", QueuePolicy::Drain),
	] {
		let cli = Cli::try_parse_from([
			"epistle",
			"account-remove",
			"--config",
			"/etc/mail.toml",
			"--name",
			"alice",
			"--queue",
			flag,
		])
		.expect("account-remove parses");
		let Command::AccountRemove {
			config,
			name,
			queue,
		} = cli.command
		else {
			panic!("expected AccountRemove, got: {:?}", cli.command);
		};
		assert_eq!(config.to_str().unwrap(), "/etc/mail.toml");
		assert_eq!(name, "alice");
		assert_eq!(queue, expected, "policy parsed for --queue {flag}");
	}
}

#[test]
fn account_remove_rejects_unknown_queue_policy() {
	let result = Cli::try_parse_from([
		"epistle",
		"account-remove",
		"--config",
		"/etc/mail.toml",
		"--name",
		"alice",
		"--queue",
		"purge",
	]);
	assert!(result.is_err(), "an unknown queue policy must be rejected");
}

#[test]
fn account_remove_requires_queue() {
	let result = Cli::try_parse_from([
		"epistle",
		"account-remove",
		"--config",
		"/etc/mail.toml",
		"--name",
		"alice",
	]);
	assert!(result.is_err(), "missing --queue must be rejected by clap");
}

/// End-to-end: a seeded account is removed through `accounts::remove`,
/// the per-record counts are printed, and the footprint (mailbox,
/// satellites, queued mail per the policy) is gone.
#[test]
fn account_remove_drops_account_and_reports_counts_to_stdout() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());

	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	store
		.add(crate::directory_store::DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: "$argon2id$placeholder".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add alice");

	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(inbox.join("a.eml"), b"Subject: hi\r\n\r\nbody\r\n").expect("write");

	store
		.masked_handle()
		.write()
		.expect("masked")
		.add("alice", "thing", "example.org", 1)
		.expect("add mask");

	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	spool
		.store(&crate::smtp::session::AcceptedMessage {
			reverse_path: "alice@example.org".to_string(),
			recipients: vec!["bob@elsewhere.example".to_string()],
			data: b"Subject: from-alice\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			no_dsn: Vec::new(),
		})
		.expect("store");

	let cfg_path = cfg.path();
	let config = crate::config::Config::load(cfg_path).expect("load config");
	let mut out = Vec::new();
	assert_eq!(
		accounts::remove(&config, "alice", QueuePolicy::Discard, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	for needle in [
		"removed account alice",
		"mailbox_files:",
		"masked_addresses: 1",
		"queued_messages_discarded: 1",
	] {
		assert!(
			text.contains(needle),
			"stdout must report `{needle}`; got: {text}"
		);
	}

	// Reopen the on-disk store so the test does not rely on the in-memory
	// store the seeding step wrote through.
	let reread = crate::directory_store::AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen");
	assert!(
		reread.dynamic("alice").is_none(),
		"the account row was removed"
	);
	assert!(!dir.path().join("accounts/alice").join("new/a.eml").exists());
	assert!(spool.list().expect("list").is_empty());
}

#[test]
fn account_remove_unknown_account_returns_failure_without_touching_storage() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let config = crate::config::Config::load(cfg.path()).expect("load config");

	let mut out = Vec::new();
	assert_eq!(
		accounts::remove(&config, "ghost", QueuePolicy::Drain, &mut out),
		ExitCode::FAILURE
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		!text.contains("removed account ghost"),
		"a missing account must not produce a success line; got: {text}"
	);
}

/// The CLI's removal helper used to call `remove_account` with
/// `None` for the bayes store regardless of `[database]`, so a
/// CLI-driven recreation always inherited the previous owner's
/// training rows. The helper now takes the store explicitly; this
/// test feeds it a `BayesStore` backed by a `connect_lazy` pool
/// (so the DELETE bubbles the lazy connect error up) and asserts
/// the call surfaces `BayesPurge` rather than returning a clean
/// success line.
#[test]
fn cli_remove_routes_a_supplied_bayes_store_into_forget_scope() {
	use crate::antispam::corpus::BayesStore;
	use std::sync::Arc;

	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let config = crate::config::Config::load(cfg.path()).expect("load");

	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	store
		.add(crate::directory_store::DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: "$argon2id$placeholder".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add alice");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");

	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let pool = runtime.block_on(async {
		sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
			.expect("lazy pool never connects")
	});
	let bayes = BayesStore::with_key(pool, [0u8; 32]);

	let mut out = Vec::new();
	let exit = accounts::remove_with_bayes(
		&runtime,
		&store,
		&spool,
		&config,
		"alice",
		QueuePolicy::Drain,
		Some(&bayes),
		&mut out,
	);
	assert_eq!(
		exit,
		ExitCode::FAILURE,
		"a failing bayes purge must abort the removal"
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("bayes corpus purge failed"),
		"the bayes store was not consulted; output was: {text}"
	);
}

/// With no bayes store passed in, the CLI silently dropped the
/// corpus purge: this is the matching control case asserting the
/// no-bayes path still finishes the on-disk work. Without the
/// fix the bayes branch in `accounts::remove` was unconditional
/// `None`, so this test would have caught that as "bayes work
/// happened when none should" — pinning both sides keeps the
/// test honest.
#[test]
fn cli_remove_completes_without_a_bayes_store() {
	use std::sync::Arc;

	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let config = crate::config::Config::load(cfg.path()).expect("load");

	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	store
		.add(crate::directory_store::DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: "$argon2id$placeholder".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add alice");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let runtime = tokio::runtime::Runtime::new().expect("runtime");

	let mut out = Vec::new();
	let exit = accounts::remove_with_bayes(
		&runtime,
		&store,
		&spool,
		&config,
		"alice",
		QueuePolicy::Drain,
		None,
		&mut out,
	);
	assert_eq!(exit, ExitCode::SUCCESS, "no-bayes path must succeed");
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("bayes_tokens_removed: 0"),
		"no-bayes path must report zero tokens dropped; got: {text}"
	);
}

/// Without a bayes store passed in, the CLI was silently dropping
/// the corpus purge; the regression test above asserts the new
/// behaviour, so this is the symmetry check: with a bayes store
/// the removal even on a missing account short-circuits to
/// `NoFound` without raising the bayes error. Pins the early
/// bail-out before any bayes work is attempted.
#[test]
fn cli_remove_reports_no_such_account_even_with_a_bayes_store() {
	use crate::antispam::corpus::BayesStore;
	use std::sync::Arc;

	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let config = crate::config::Config::load(cfg.path()).expect("load");

	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let pool = runtime.block_on(async {
		sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
			.expect("lazy pool never connects")
	});
	let bayes = BayesStore::with_key(pool, [0u8; 32]);

	let mut out = Vec::new();
	let exit = accounts::remove_with_bayes(
		&runtime,
		&store,
		&spool,
		&config,
		"ghost",
		QueuePolicy::Drain,
		Some(&bayes),
		&mut out,
	);
	assert_eq!(exit, ExitCode::FAILURE, "unknown account must fail");
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		!text.contains("bayes corpus purge failed"),
		"a missing account must short-circuit before the bayes purge runs; got: {text}"
	);
}
