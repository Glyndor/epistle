//! Tests for the `mail suppression` command.

use super::*;
use crate::queue::SuppressionList;
use std::collections::BTreeMap;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn lists_and_removes_suppressed_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	SuppressionList::open(dir.path())
		.expect("open")
		.suppress("bob@example.net");

	// List shows the suppressed address.
	let mut out = Vec::new();
	assert_eq!(run_legacy(&config, None, None, &mut out), ExitCode::SUCCESS);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob@example.net\n");

	// Remove clears it.
	let mut out = Vec::new();
	assert_eq!(
		run_legacy(&config, Some("bob@example.net"), None, &mut out),
		ExitCode::SUCCESS
	);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}

#[test]
fn lists_and_removes_per_account_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	SuppressionList::open(dir.path())
		.expect("open")
		.suppress_for("alice@example.org", "bob@example.net");

	// The global list is empty; the per-account list shows the address.
	let mut out = Vec::new();
	assert_eq!(run_legacy(&config, None, None, &mut out), ExitCode::SUCCESS);
	assert!(out.is_empty());

	let mut out = Vec::new();
	assert_eq!(
		run_legacy(&config, None, Some("alice@example.org"), &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob@example.net\n");

	// Remove scoped to the account clears it.
	let mut out = Vec::new();
	assert_eq!(
		run_legacy(
			&config,
			Some("bob@example.net"),
			Some("alice@example.org"),
			&mut out
		),
		ExitCode::SUCCESS
	);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed_for("alice@example.org", "bob@example.net")
	);
}

#[test]
fn add_suppresses_globally_and_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());

	let mut out = Vec::new();
	assert_eq!(
		add(&config, "Bob@Example.NET", None, false, &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		"suppressed bob@example.net\n"
	);
	let list = SuppressionList::open(dir.path()).expect("open");
	assert!(list.is_suppressed("bob@example.net"));
	assert!(!list.is_suppressed_for("alice@example.org", "bob@example.net"));

	let mut out = Vec::new();
	assert_eq!(
		add(
			&config,
			"carol@example.net",
			Some("alice@example.org"),
			false,
			&mut out
		),
		ExitCode::SUCCESS
	);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		"suppressed carol@example.net for alice@example.org\n"
	);
	let list = SuppressionList::open(dir.path()).expect("open");
	assert!(list.is_suppressed_for("alice@example.org", "carol@example.net"));
	assert!(!list.is_suppressed("carol@example.net"));
}

#[test]
fn add_refuses_something_that_is_not_an_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		add(&config, "not an address", None, false, &mut out),
		ExitCode::from(2)
	);
	assert!(out.is_empty());
	assert!(
		SuppressionList::open(dir.path())
			.expect("open")
			.list()
			.is_empty()
	);
}

#[test]
fn parses_add_and_keeps_the_flat_form() {
	use clap::Parser;
	let parse = |args: &[&str]| {
		let mut argv = vec!["epistle", "suppression"];
		argv.extend(args);
		crate::cli::Cli::try_parse_from(argv).expect("parses")
	};
	let crate::cli::Command::Suppression { action, .. } =
		parse(&["add", "bob@example.net", "--account", "alice@example.org"]).command
	else {
		panic!("not a suppression command");
	};
	let Some(SuppressionCli::Add {
		address, account, ..
	}) = action
	else {
		panic!("add did not parse");
	};
	assert_eq!(address, "bob@example.net");
	assert_eq!(account.as_deref(), Some("alice@example.org"));

	let crate::cli::Command::Suppression {
		action,
		remove,
		account,
		..
	} = parse(&[
		"--remove",
		"bob@example.net",
		"--account",
		"alice@example.org",
	])
	.command
	else {
		panic!("not a suppression command");
	};
	assert!(action.is_none());
	assert_eq!(remove.as_deref(), Some("bob@example.net"));
	assert_eq!(account.as_deref(), Some("alice@example.org"));
}

/// Counts connection attempts and always refuses them, so a test can tell a
/// skipped recipient (no attempt) from an attempted one.
struct CountingConnector(std::sync::atomic::AtomicUsize);

impl crate::queue::Connector for CountingConnector {
	fn connect(
		&self,
		_domain: &str,
		_policy: Option<&crate::mtasts::Policy>,
	) -> crate::queue::resolver::ConnectFuture<'_> {
		self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
		Box::pin(async {
			Err(crate::queue::client::DeliveryError::Transient(
				"connection refused".into(),
			))
		})
	}
}

/// Queue one message from `alice@example.org` to `bob@example.net`, run one
/// delivery pass and report (connection attempts, entries left in the spool).
async fn deliver_once(data_dir: &std::path::Path) -> (usize, usize) {
	use crate::smtp::session::AcceptedMessage;
	let spool = crate::storage::FsSpool::open(data_dir).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@example.net".to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let connector = std::sync::Arc::new(CountingConnector(Default::default()));
	let worker = crate::queue::Worker::new(spool, connector.clone(), "mail.example.org")
		.with_suppression(SuppressionList::open(data_dir).expect("open"));
	worker.pass().await.expect("pass");
	let attempts = connector.0.load(std::sync::atomic::Ordering::SeqCst);
	let left = crate::storage::FsSpool::open(data_dir)
		.expect("spool")
		.list()
		.expect("list")
		.len();
	(attempts, left)
}

#[tokio::test]
async fn delivery_skips_an_address_added_from_the_cli() {
	// Control: with nothing suppressed the worker tries to connect and keeps
	// the message for a retry.
	let control = tempfile::tempdir().expect("tempdir");
	assert_eq!(deliver_once(control.path()).await, (1, 1));

	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		add(&config, "bob@example.net", None, false, &mut Vec::new()),
		ExitCode::SUCCESS
	);
	assert_eq!(
		deliver_once(dir.path()).await,
		(0, 0),
		"no connection and the entry is dropped"
	);
}

#[tokio::test]
async fn delivery_skips_per_account_only_for_that_account() {
	let mine = tempfile::tempdir().expect("tempdir");
	let config_mine = config(mine.path());
	add(
		&config_mine,
		"bob@example.net",
		Some("alice@example.org"),
		false,
		&mut Vec::new(),
	);
	assert_eq!(deliver_once(mine.path()).await, (0, 0));

	let other = tempfile::tempdir().expect("tempdir");
	let config_other = config(other.path());
	add(
		&config_other,
		"bob@example.net",
		Some("someone@example.org"),
		false,
		&mut Vec::new(),
	);
	assert_eq!(deliver_once(other.path()).await, (1, 1));
}
