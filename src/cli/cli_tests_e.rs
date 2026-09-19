//! CLI tests for the `[database]` unreachable-database abort and
//! the stdout/stderr split.
//!
//! Split into a sibling file so `cli_tests_c.rs` keeps below the
//! per-file line budget. The tests here drive the public
//! `accounts::remove` (the dispatch path is covered elsewhere); the
//! distinguishing concern is the `[database]` section the operator
//! has actually configured: an unreachable URL must abort before
//! the on-disk work starts, and any error wording that emerges must
//! stay on stderr so the count summary on stdout stays scriptable.

use super::*;
use crate::directory_store::removal::QueuePolicy;

/// A `[database]` URL that points at a closed local port must refuse
/// the removal rather than run the on-disk work with `None`. The
/// `connect_database` helper that drives the CLI's bayes bootstrap
/// returns `Ok(None)` for an unreachable database (it only fails
/// hard when `[database] directory = true`); `open_bayes_store`
/// used to accept that answer and `remove_with_bayes` therefore
/// did the on-disk work without a corpus purge. A recreated account
/// name after such a removal inherits the previous user's training;
/// this test pins the abort by binding to `127.0.0.1:0`, reading the
/// kernel-assigned port, dropping the listener (so the port is open
/// and refuses connections), pointing `[database].url` at it, then
/// asserting the mailbox and the `accounts.toml` row are still
/// present after the CLI says FAILURE.
///
/// Sabotaged by reverting `open_bayes_store` to proceed when the
/// pool returns `None`: the test then surfaces both that
/// `ExitCode` was `SUCCESS` and the dynamic-account row is gone.
#[test]
fn cli_remove_aborts_when_a_configured_database_is_unreachable() {
	use std::io::Write as _;
	use std::net::TcpListener;

	let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
	let port = listener.local_addr().expect("local addr").port();
	drop(listener);

	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		r#"hostname = "mail.example.org"
data_dir = {:?}
domains = ["example.org"]

[database]
url = "postgres://127.0.0.1:{port}/none?sslmode=require"
"#,
		dir.path()
	);
	let mut cfg_file = tempfile::NamedTempFile::new().expect("temp file");
	cfg_file.write_all(toml.as_bytes()).expect("write cfg");
	let config = crate::config::Config::load(cfg_file.path()).expect("load config");

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
	std::fs::create_dir_all(&inbox).expect("mkdir inbox");
	let email = inbox.join("a.eml");
	std::fs::write(&email, b"Subject: hi\r\n\r\nbody\r\n").expect("write message");

	let mut out = Vec::new();
	let exit = accounts::remove(&config, "alice", QueuePolicy::Discard, &mut out);
	assert_eq!(
		exit,
		ExitCode::FAILURE,
		"unreachable [database] must abort the removal"
	);

	assert!(
		email.exists(),
		"the mailbox file must still be present after an aborted removal"
	);
	assert!(
		inbox.is_dir(),
		"the mailbox directory must still be present after an aborted removal"
	);
	let reread = crate::directory_store::AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen store");
	assert!(
		reread.dynamic("alice").is_some(),
		"the dynamic-account row must survive an aborted removal"
	);
}

/// The same failing case as the abort test, with the additional
/// guard that the CLI's error/warning output reaches stderr and
/// leaves stdout carrying only the count summary. A regression that
/// puts `error: ...` lines on `out` instead of routing them through
/// `super::style::error`/`style::warn` would feed structured errors
/// into whatever pipes the count summary downstream; the assertion
/// here is the one that flags that.
///
/// Sabotaged by re-introducing a `writeln!(out, "error: ...")`
/// inside the unreachable-database branch (or any of the bayes
/// error paths in `accounts::remove`); the test then surfaces
/// `"error:" in stdout was <text>`.
#[test]
fn cli_remove_error_lines_do_not_pollute_stdout() {
	use std::io::Write as _;
	use std::net::TcpListener;

	let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
	let port = listener.local_addr().expect("local addr").port();
	drop(listener);

	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		r#"hostname = "mail.example.org"
data_dir = {:?}
domains = ["example.org"]

[database]
url = "postgres://127.0.0.1:{port}/none?sslmode=require"
"#,
		dir.path()
	);
	let mut cfg_file = tempfile::NamedTempFile::new().expect("temp file");
	cfg_file.write_all(toml.as_bytes()).expect("write cfg");
	let config = crate::config::Config::load(cfg_file.path()).expect("load config");

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

	let mut out = Vec::new();
	let exit = accounts::remove(&config, "alice", QueuePolicy::Discard, &mut out);
	assert_eq!(exit, ExitCode::FAILURE, "unreachable database must abort");

	let text = String::from_utf8(out).expect("utf8 stdout");
	assert!(
		!text.contains("error:"),
		"stdout must not carry error: lines; got: {text:?}"
	);
}
