//! Tests for the dynamic-store file watcher.
//!
//! Every test drives `FileWatcher::poll` directly so the assertions
//! stay deterministic. The background `spawn` path is verified by
//! `runs_until_dropped_and_picks_up_changes_in_a_runtime`, which holds
//! the lease for a couple of poll intervals and asserts the live reload.

use std::sync::Arc;

use super::FileWatcher;
use crate::smtp::address::Address;
use crate::smtp::auth::tests::{fixture_password, wrong_password};
use crate::smtp::directory::Resolution;
use crate::{
	config::Account,
	directory_store::{AccountStore, DynamicAccount},
	storage::write_secret,
};

fn static_alice() -> Account {
	Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some(crate::smtp::auth::tests::hash(fixture_password())),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

fn open_store(dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![static_alice()],
	)
	.expect("open store")
}

fn dynamic(name: &str, address: &str) -> DynamicAccount {
	let mut account = DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: "$argon2id$stub".to_string(),
		scram: None,
		totp_secret: None,
		disabled: false,
		allowed_protocols: None,
	};
	account.password_hash = crate::smtp::auth::tests::hash(fixture_password());
	account
}

fn resolves(handle: &crate::directory_store::DirectoryHandle, raw: &str) -> Resolution {
	handle
		.current()
		.resolve(&Address::parse(raw).expect("address"))
}

/// Poll once: nothing on disk has changed yet, so every watched file
/// reports `Unchanged`. The directory resolution does not move. The
/// seed poll happens before the `add` so the watcher observes the
/// post-add fingerprints and the second poll is truly a no-op.
#[test]
fn poll_with_no_change_is_a_noop() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	// Plant an entry through the in-server mutator so the directory
	// has something to keep.
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));
	// First poll establishes the current state; the second is the
	// real assertion.
	let _ = watcher.poll();
	let report = watcher.poll();
	for event in &report.events {
		// A file that exists but did not move reports `Unchanged`;
		// a file that has never existed reports `Absent`. Both mean
		// "no work this poll".
		assert!(
			matches!(
				event,
				super::PollEvent::Unchanged(_) | super::PollEvent::Absent(_)
			),
			"got {event:?}",
		);
	}
	assert_eq!(
		resolves(&store.handle(), "bob@example.org"),
		Resolution::Account("bob".to_string()),
	);
}

/// Poll picks up a brand-new `accounts.toml` that the file watcher
/// never saw at startup. The CLI-equivalent write (atomic, owner-only)
/// lands, the next poll reads it, and the directory swaps.
#[test]
fn poll_picks_up_a_new_accounts_toml() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));
	// Seed: first poll so the watcher learns the startup fingerprints.
	let _ = watcher.poll();
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::UnknownUser,
	);

	// Write the file as if the CLI did it: `write_secret` is the
	// atomic, owner-only writer every CLI command uses.
	let text = r#"
[[accounts]]
name = "carol"
addresses = ["carol@example.org"]
password_hash = "stub"
"#;
	write_secret(&dir.path().join("accounts.toml"), text.as_bytes()).expect("write");

	let report = watcher.poll();
	let loaded = report
		.events
		.iter()
		.filter(|event| matches!(event, super::PollEvent::Loaded(super::PollTarget::Accounts)))
		.count();
	assert_eq!(loaded, 1, "accounts.toml must be reported as loaded once");
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::Account("carol".to_string()),
	);
}

/// A bad file does NOT replace the running directory. The poll
/// reports the parse failure on the bad-version path and stays silent
/// on repeats with the same fingerprint.
#[test]
fn poll_keeps_the_directory_when_a_file_fails_to_parse() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));

	// Rewrite accounts.toml with syntactically-broken content (a
	// half-written file would look the same to a watcher).
	write_secret(
		&dir.path().join("accounts.toml"),
		b"this is not = = valid toml",
	)
	.expect("write bad");
	let report = watcher.poll();
	assert!(
		report.events.iter().any(|event| matches!(
			event,
			super::PollEvent::BadParse(super::PollTarget::Accounts)
		)),
		"poll must report a parse failure: {report:?}",
	);
	// The running directory is unchanged.
	assert_eq!(
		resolves(&store.handle(), "bob@example.org"),
		Resolution::Account("bob".to_string()),
		"a bad file must not invalidate the running directory",
	);

	// A repeat poll with the same bad fingerprint does not report the
	// BadParse event twice, the warning is deduped by fingerprint.
	let report = watcher.poll();
	let bad_parses = report
		.events
		.iter()
		.filter(|event| {
			matches!(
				event,
				super::PollEvent::BadParse(super::PollTarget::Accounts)
			)
		})
		.count();
	assert_eq!(
		bad_parses, 0,
		"repeated bad poll with the same fingerprint must stay silent: {report:?}",
	);

	// Recover: the operator fixes the file, the watcher picks the
	// change up on the very next poll.
	let fixed = r#"
[[accounts]]
name = "carol"
addresses = ["carol@example.org"]
password_hash = "stub"
"#;
	write_secret(&dir.path().join("accounts.toml"), fixed.as_bytes()).expect("write fixed");
	let report = watcher.poll();
	assert!(
		report
			.events
			.iter()
			.any(|event| matches!(event, super::PollEvent::Loaded(super::PollTarget::Accounts))),
		"the recovered file must be loaded on the next poll: {report:?}",
	);
	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::Account("carol".to_string()),
	);
}

/// A removal the CLI performed by rewriting `accounts.toml` reaches
/// the running directory: the address stops resolving the moment the
/// file disappears or is rewritten without the row.
#[test]
fn poll_picks_up_a_removal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	store.add(dynamic("bob", "bob@example.org")).expect("add");
	let handle = store.handle();
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));
	let _ = watcher.poll();

	// CLI rewrote accounts.toml without the row.
	let text = r#"
[[accounts]]
name = "carol"
addresses = ["carol@example.org"]
password_hash = "stub"
"#;
	write_secret(&dir.path().join("accounts.toml"), text.as_bytes()).expect("write");
	watcher.poll();
	assert_eq!(
		resolves(&handle, "bob@example.org"),
		Resolution::UnknownUser,
		"a removed account must stop resolving after the reload",
	);
}

/// A new `app_passwords.toml` reaches the directory and makes the
/// secondary credential authenticate from the next request.
#[test]
fn poll_picks_up_a_new_app_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(open_store(dir.path()));
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));
	let _ = watcher.poll();

	let wrong = wrong_password();
	let secret = uuid::Uuid::now_v7().simple().to_string();
	let hash = crate::smtp::auth::tests::hash(&secret);
	// `wrong_password()` keeps the primary credential wrong, the
	// app-password path runs, this assertion checks the swap step.
	let _ = wrong;
	let text = format!(
		r#"[accounts.alice]
passwords = [
  {{ label = "phone", hash = "{hash}" }}
]
"#
	);
	write_secret(&dir.path().join("app_passwords.toml"), text.as_bytes()).expect("write");
	watcher.poll();
	let directory = store.handle().current();
	assert_eq!(
		directory
			.authenticate("alice", &secret, crate::config::Protocol::Api)
			.as_deref(),
		Some("alice"),
		"app password from the reload must authenticate",
	);
}

/// The background loop picks up changes: drive a `spawn` against a
/// real `tokio::runtime::Runtime` with a short interval and assert the
/// address the CLI just added resolves within the deadline.
#[test]
fn spawned_loop_picks_up_changes_within_a_short_interval() {
	let dir = tempfile::tempdir().expect("tempdir");
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime");
	let _guard = runtime.enter();
	let store = Arc::new(open_store(dir.path()));
	let watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&store));
	let handle = watcher.spawn(std::time::Duration::from_millis(50));

	// Give the loop one tick to settle the seeding poll.
	runtime.block_on(async {
		tokio::time::sleep(std::time::Duration::from_millis(60)).await;
	});

	// Write a new row, mimicking what `mail account-add` does after the
	// CLI process exits.
	let text = r#"
[[accounts]]
name = "carol"
addresses = ["carol@example.org"]
password_hash = "stub"
"#;
	write_secret(&dir.path().join("accounts.toml"), text.as_bytes()).expect("write");

	// The 5 s requirement reduces, in this test, to "the change shows
	// up within the poll interval". 50 ms × a few ticks is plenty.
	runtime.block_on(async {
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	});

	assert_eq!(
		resolves(&store.handle(), "carol@example.org"),
		Resolution::Account("carol".to_string()),
		"the spawned watcher must pick up the CLI's accounts.toml write",
	);

	// Tell the task to wind down so the runtime can drop.
	handle.abort();
	let _ = runtime.block_on(handle);
}

/// Integration-style: a separate `AccountStore` writes the same way
/// the CLI does (open → `add` → atomic write), and the watcher's
/// running handle resolves the new address after the next poll. The
/// two stores never share a process-local cache; only the filesystem
/// carries the change, which is the whole point of the watcher.
#[test]
fn poll_picks_up_a_write_from_a_separate_store_instance() {
	let dir = tempfile::tempdir().expect("tempdir");
	let server = Arc::new(open_store(dir.path()));
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::clone(&server));
	let _ = watcher.poll();
	assert_eq!(
		resolves(&server.handle(), "carol@example.org"),
		Resolution::UnknownUser,
	);

	// A fresh AccountStore, opened as if by the CLI process.
	let cli = Arc::new(open_store(dir.path()));
	// The CLI creates accounts via `AccountStore::add`, which goes
	// through `with_password` → argon2id hash → `persist` →
	// `write_secret`. The whole chain is the path the watcher has to
	// observe through `accounts.toml`.
	let cli_account = crate::directory_store::DynamicAccount::with_password(
		"carol".to_string(),
		vec!["carol@example.org".to_string()],
		fixture_password(),
	)
	.expect("hashed account");
	cli.add(cli_account).expect("cli add");

	// The watcher's running handle must see the new address on the
	// very next poll, no sleep needed; the write already landed
	// before this call.
	watcher.poll();
	assert_eq!(
		resolves(&server.handle(), "carol@example.org"),
		Resolution::Account("carol".to_string()),
		"a write from a sibling AccountStore must show up after one poll",
	);
}
