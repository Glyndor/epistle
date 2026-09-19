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

/// The same failing case as the abort test, but driven through
/// `remove_with_bayes` with an explicit `BayesStore` on a lazy pool
/// so the helper reaches the `BayesPurge` arm of the failure path and
/// the operator-facing warning and error lines both fire. The split
/// between `out` and `err` is what the rest of the CLI promises: a
/// piped run still sees only the count summary on stdout, while the
/// operator's terminal sees the `warning:` about the retained
/// account and the `error:` carrying the underlying purge failure.
///
/// Three assertions pin the split: the exit code, the contents of
/// the captured `err` sink, and the absence of either line on `out`.
/// A regression that wrote `error: ...` or `warning: ...` to `out`
/// (the original bug the test was supposed to catch, but never did
/// because the unreachable-database branch never reached the Bayes
/// arm and never wrote anything at all) fails the second assertion
/// pair; a regression that swallowed the warning fails the third.
///
/// Sabotaged by re-introducing `writeln!(out, "warning: ...")`
/// inside the BayesPurge arm of `remove_with_bayes`: the third
/// assertion then surfaces `stdout must not carry warning: lines;
/// got: "warning: ..."`.
#[test]
fn cli_remove_error_lines_do_not_pollute_stdout() {
	use crate::antispam::corpus::BayesStore;
	use crate::cli::tests_b::config_at;
	use std::sync::Arc;

	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let config = crate::config::Config::load(cfg.path()).expect("load config");

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
		sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none").expect("lazy pool never connects")
	});
	let bayes = BayesStore::with_key(pool, [0u8; 32]);

	let mut out = Vec::new();
	let mut err_buf = Vec::new();
	let mut err_stream = anstream::AutoStream::new(&mut err_buf, anstream::ColorChoice::Auto);
	let exit = accounts::remove_with_bayes(
		&runtime,
		&store,
		&spool,
		&config,
		"alice",
		QueuePolicy::Discard,
		Some(&bayes),
		&mut out,
		&mut err_stream,
	);
	assert_eq!(
		exit,
		ExitCode::FAILURE,
		"a failing bayes purge must abort the removal"
	);

	let err_text = String::from_utf8(err_buf).expect("utf8 err");
	assert!(
		err_text.contains("warning:"),
		"the warning about the retained account must reach stderr; got: {err_text:?}"
	);
	assert!(
		err_text.contains("bayes corpus purge failed"),
		"the warning line must name the bayes purge; got: {err_text:?}"
	);
	assert!(
		err_text.contains("error:"),
		"the purge failure must reach stderr; got: {err_text:?}"
	);

	let out_text = String::from_utf8(out).expect("utf8 stdout");
	assert!(
		!out_text.contains("error:"),
		"stdout must not carry error: lines; got: {out_text:?}"
	);
	assert!(
		!out_text.contains("warning:"),
		"stdout must not carry warning: lines; got: {out_text:?}"
	);
	assert!(
		!out_text.contains("bayes corpus purge failed"),
		"stdout must not carry the bayes warning; got: {out_text:?}"
	);
}
