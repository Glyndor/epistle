//! Cross-process locking tests for the dynamic-account, app-password,
//! masked-address and API-key stores.
//!
//! The CLI and the running server are separate processes that mutate
//! the same backing file. Without serialisation a CLI `epistle account
//! add ...` that runs between the server's read and write disappears
//! when the server persists its own state from a stale in-memory copy.
//! These tests load two `AccountStore` (or app-password / masked /
//! API-key) handles on the same data directory, add a different row
//! through each, and confirm both rows reach the on-disk file after
//! the writes. The handles live in the same process, so they exercise
//! the "re-read under the lock" half of the contract; the cross-process
//! half rests on the lock primitive whose own tests are in
//! [`crate::storage::lock_tests`].

use std::thread;

use crate::api::api_keys::Scope;
use crate::api::api_keys::{ApiKey, ApiKeyStore};
use crate::directory_store::{
	AccountStore, AppPassword, AppPasswordStore, DynamicAccount, MaskedAddressStore,
};
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::scram::ScramStored;

fn open_store(dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![],
	)
	.expect("open store")
}

/// Two `AccountStore` handles opened on the same data dir simulate
/// CLI and server: the server's in-memory copy is stale (it predates
/// the CLI's write), but the re-read-before-mutate contract still
/// commits both rows. Without the cross-process lock + fresh read, the
/// CLI's `alpha` row would be silently overwritten when the server
/// persisted its own (empty) state.
#[test]
fn two_account_store_handles_lose_no_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Server store: loaded before any write. In-memory state stays
	// empty across the CLI's mutation until the next mutator runs.
	let server = open_store(dir.path());

	// CLI store: a separate handle, read from disk at construction,
	// mutated to add alpha. The disk now contains alpha.
	let dir_for_cli = dir.path().to_path_buf();
	let cli_thread = thread::spawn(move || {
		let cli = open_store(&dir_for_cli);
		cli.add(DynamicAccount {
			name: "alpha".to_string(),
			addresses: vec!["alpha@example.org".to_string()],
			password_hash: "$argon2id$cli".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
		})
		.expect("cli add alpha");
	});
	cli_thread.join().expect("cli thread");

	// Server's in-memory state is still empty here. With the contract
	// in place, the add sees the post-CLI on-disk state under the lock
	// and persists `[alpha, bravo]`. Without it the server would write
	// just `[bravo]` and lose alpha.
	server
		.add(DynamicAccount {
			name: "bravo".to_string(),
			addresses: vec!["bravo@example.org".to_string()],
			password_hash: "$argon2id$server".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
		})
		.expect("server add bravo");

	let handle_after = std::fs::read_to_string(dir.path().join("accounts.toml")).expect("read");
	assert!(
		handle_after.contains("alpha"),
		"alpha added by the CLI must survive the server's add: {handle_after}"
	);
	assert!(
		handle_after.contains("bravo"),
		"bravo added by the server must be in the file: {handle_after}"
	);

	let reopened = open_store(dir.path());
	let directory = reopened.handle().current();
	let resolved_alpha = directory.resolve(&Address::parse("alpha@example.org").expect("a"));
	let resolved_bravo = directory.resolve(&Address::parse("bravo@example.org").expect("b"));
	assert_eq!(resolved_alpha, Resolution::Account("alpha".to_string()));
	assert_eq!(resolved_bravo, Resolution::Account("bravo".to_string()));
}

/// Same shape as the account-store test, but driven through the
/// `AppPasswordStore` so a CLI `epistle app-password add` and a server
/// `app-password add` both end up in `app_passwords.toml`. The CLI
/// handle goes through a thread so the in-memory mirror really is
/// stale when the main thread commits its own write.
#[test]
fn two_app_password_handles_lose_no_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut cli_state = AppPasswordStore::open(dir.path()).expect("cli open");

	let cli_dir = dir.path().to_path_buf();
	let cli_thread = thread::spawn(move || {
		let mut cli = AppPasswordStore::open(&cli_dir).expect("cli open");
		cli.add(
			"alice",
			AppPassword {
				label: "phone".to_string(),
				hash: "$argon2id$cli".to_string(),
				expires_at: None,
				ip_cidr: None,
			},
		)
		.expect("cli add phone");
	});
	cli_thread.join().expect("cli thread");

	// `cli_state` is the in-memory mirror bound to the test thread.
	// Mutating through it after the CLI thread persisted the row is
	// the same race a CLI-vs-server scenario produces: without the
	// re-read-before-mutate path, only "laptop" would land.
	cli_state
		.add(
			"alice",
			AppPassword {
				label: "laptop".to_string(),
				hash: "$argon2id$server".to_string(),
				expires_at: None,
				ip_cidr: None,
			},
		)
		.expect("server add laptop");

	let reopened = AppPasswordStore::open(dir.path()).expect("reopen");
	let rows = reopened.list();
	let labels: Vec<&str> = rows.iter().map(|(_, label, _, _)| label.as_str()).collect();
	assert!(
		labels.contains(&"phone"),
		"phone added by the CLI must survive the server's add: {labels:?}"
	);
	assert!(
		labels.contains(&"laptop"),
		"laptop added by the server must persist: {labels:?}"
	);
}

/// Same shape, this time through the API-key store that the bearer
/// middleware reads from. The lock + re-read path applies to
/// `api_keys.toml` the same way it does to the dynamic-account file.
#[test]
fn two_api_key_handles_lose_no_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut cli_state = ApiKeyStore::open(dir.path()).expect("cli open");

	let cli_dir = dir.path().to_path_buf();
	let cli_thread = thread::spawn(move || {
		let mut cli = ApiKeyStore::open(&cli_dir).expect("cli open");
		cli.add(ApiKey {
			label: "reader".to_string(),
			hash: "sha256:$1".to_string(),
			expires_at: None,
			ip_cidr: None,
			scopes: vec![Scope::Read.as_str().to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("cli add reader");
	});
	cli_thread.join().expect("cli thread");

	cli_state
		.add(ApiKey {
			label: "writer".to_string(),
			hash: "sha256:$2".to_string(),
			expires_at: None,
			ip_cidr: None,
			scopes: vec![Scope::Write.as_str().to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("server add writer");

	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	let mut labels: Vec<String> = reopened.list().into_iter().map(|row| row.label).collect();
	labels.sort();
	assert_eq!(
		labels,
		vec!["reader".to_string(), "writer".to_string()],
		"both keys must survive a concurrent write"
	);
}

/// Two masked-address handles: the CLI adds one entry and the server,
/// carrying a stale in-memory mirror, adds another. Both reach the
/// on-disk JSON and the reloaded store sees them.
#[test]
fn two_masked_address_handles_lose_no_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut cli_state = MaskedAddressStore::open(dir.path()).expect("cli open");

	let cli_dir = dir.path().to_path_buf();
	let cli_thread = thread::spawn(move || {
		let mut cli = MaskedAddressStore::open(&cli_dir).expect("cli open");
		cli.add("alice", "shop", "example.org", 1)
			.expect("cli add shop");
	});
	cli_thread.join().expect("cli thread");

	cli_state
		.add("alice", "list", "example.org", 2)
		.expect("server add list");

	let reopened = MaskedAddressStore::open(dir.path()).expect("reopen");
	let views = reopened.list_for_account("alice");
	assert_eq!(
		views.len(),
		2,
		"both masked entries must survive a concurrent write; got {views:?}"
	);
}

/// Confirm a CLI-side write to `accounts.toml` reaches a separate
/// server-side handle after the server's next mutation: the same
/// payload the file watcher would pick up in production, with the
/// lock + re-read path proving it landed without half-written bytes.
/// The server's in-memory mirror is stale across the CLI write
/// (handle is what `Accept`s pre-CLI), but the next mutator
/// re-reads the file under the lock and rolls the CLI's row in.
#[test]
fn cli_write_round_trips_to_a_fresh_directory_handle() {
	let dir = tempfile::tempdir().expect("tempdir");
	let server = open_store(dir.path());

	// CLI writes the file directly the way `epistle account add`
	// would in production: through the store, after we seeded the
	// file with an empty config.
	let cli_dir = dir.path().to_path_buf();
	let cli_thread = thread::spawn(move || {
		let cli = open_store(&cli_dir);
		cli.add(DynamicAccount {
			name: "carol".to_string(),
			addresses: vec!["carol@example.org".to_string()],
			password_hash: "$argon2id$cli".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
		})
		.expect("cli add");
	});
	cli_thread.join().expect("cli");

	let handle = server.handle();
	// Pre-mutation the server's handle still does not see carol: the
	// file watcher would have picked up the CLI's write after a
	// poll, but a same-process sibling that does not run the
	// watcher's poll loop stays stale until its own next mutator
	// triggers the re-read. This is the same shape the SCRAM
	// upgrader hits on a hot path.
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("carol@example.org").expect("a")),
		Resolution::UnknownUser,
		"handle does not see the CLI write until the next mutator re-reads from disk",
	);

	// Trigger a server-side mutator. Its `mutate_store` re-reads
	// from disk under the cross-process `flock`, so carol lands in
	// the post-write in-memory mirror.
	let _ = server.set_password_hash(
		"carol",
		"$argon2id$upgraded".to_string(),
		Some(ScramStored::with_fresh_salt("hunter2").expect("scram")),
	);
	assert_eq!(
		handle
			.current()
			.resolve(&Address::parse("carol@example.org").expect("a")),
		Resolution::Account("carol".to_string()),
		"the server's mutator must observe the CLI's write via the re-read",
	);
}
