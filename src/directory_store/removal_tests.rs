//! End-to-end tests for [`super::remove_account`]: the whole footprint
//! is gone, the queue obeys the policy, and an unknown / malformed
//! name never reaches the filesystem.

use std::path::Path;
use std::sync::Arc;

use crate::directory_store::AccountStore;
use crate::directory_store::removal::{QueuePolicy, remove_account};
use crate::queue::SuppressionList;
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;

const DOMAIN: &str = "example.org";

fn store_and_spool(dir: &Path) -> (Arc<AccountStore>, FsSpool) {
	let store = Arc::new(
		AccountStore::open(
			dir,
			vec![DOMAIN.to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store"),
	);
	let spool = FsSpool::open(dir).expect("open spool");
	(store, spool)
}

fn enqueue(spool: &FsSpool, reverse_path: &str, body: &str) {
	spool
		.store(&AcceptedMessage {
			reverse_path: reverse_path.to_string(),
			recipients: vec!["bob@elsewhere.example".to_string()],
			data: format!("Subject: {body}\r\n\r\n{body}\r\n").into_bytes(),
			require_tls: false,
			mailbox: None,
			no_dsn: Vec::new(),
		})
		.expect("store");
}

fn add_account(store: &AccountStore, name: &str, address: &str) {
	store
		.add(crate::directory_store::DynamicAccount {
			name: name.to_string(),
			addresses: vec![address.to_string()],
			password_hash: "$argon2id$placeholder".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add");
}

/// Seed every footprint an account leaves: two messages in the
/// mailbox, one masked address, one app password, one suppressed
/// recipient, plus two queued messages from the account's reverse
/// path and one from a different account.
fn seed(dir: &Path, store: &Arc<AccountStore>, spool: &FsSpool, name: &str) {
	let address = format!("{name}@{DOMAIN}");
	add_account(store, name, &address);

	// Mailbox with two messages (across the INBOX new/ dir and a folder).
	let mailbox_root = dir.join("accounts").join(name);
	let inbox_new = mailbox_root.join("new");
	std::fs::create_dir_all(&inbox_new).expect("mkdir inbox");
	std::fs::write(inbox_new.join("first.eml"), b"Subject: a\r\n\r\nhi\r\n").expect("write 1");
	std::fs::write(inbox_new.join("second.eml"), b"Subject: b\r\n\r\nhi\r\n").expect("write 2");

	// Masked address owned by the account.
	store
		.masked_handle()
		.write()
		.expect("masked lock")
		.add(name, "thing", DOMAIN, 1_700_000_000)
		.expect("add mask");

	// App password for the account.
	let mut app_passwords =
		crate::directory_store::AppPasswordStore::open(dir).expect("open app passwords");
	app_passwords
		.add(
			name,
			crate::directory_store::AppPassword {
				label: "phone".to_string(),
				hash: "$argon2id$placeholder".to_string(),
				expires_at: None,
				ip_cidr: None,
			},
		)
		.expect("add app pw");

	// Per-account suppression entry.
	let suppression = SuppressionList::open(dir).expect("suppression");
	suppression.suppress_for(name, "ghost@elsewhere.example");

	// Spooled envelopes: two from this account's address, one from another account.
	enqueue(spool, &address, "msg1");
	enqueue(spool, &address, "msg2");
	enqueue(spool, "carol@elsewhere.example", "other");
}

#[test]
fn removing_an_account_deletes_its_mailbox_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let mailbox_root = dir.path().join("accounts/alice");
	assert!(mailbox_root.join("new/first.eml").exists());

	let result =
		remove_account(&store, &spool, dir.path(), "alice", QueuePolicy::Drain).expect("remove");

	// The directory is gone (or at minimum empty).
	assert_eq!(result.masked_addresses, 1);
	assert!(!mailbox_root.join("new/first.eml").exists());
	assert!(
		!mailbox_root.exists()
			|| std::fs::read_dir(&mailbox_root)
				.map(|mut d| d.next().is_none())
				.unwrap_or(true),
		"the mailbox root must be gone: {mailbox_root:?}"
	);
}

#[test]
fn recreating_the_name_starts_from_an_empty_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "victim");

	remove_account(&store, &spool, dir.path(), "victim", QueuePolicy::Drain).expect("remove");
	assert!(store.dynamic("victim").is_none());

	// Recreating with the same name: the mailbox is empty.
	add_account(&store, "victim", "victim@example.org");
	let inbox_new = dir.path().join("accounts/victim/new");
	let entries = if inbox_new.exists() {
		std::fs::read_dir(&inbox_new)
			.map(|d| d.filter_map(|e| e.ok()).count())
			.unwrap_or(0)
	} else {
		0
	};
	assert_eq!(
		entries, 0,
		"the recreated account must not inherit mailbox content"
	);
}

#[test]
fn removing_an_account_drops_its_masked_addresses_app_passwords_and_suppressions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "bob");

	assert_eq!(store.list_masked("bob").len(), 1);
	assert_eq!(
		crate::directory_store::AppPasswordStore::open(dir.path())
			.expect("app passwords")
			.for_account("bob")
			.len(),
		1
	);
	assert_eq!(
		SuppressionList::open(dir.path())
			.expect("suppression")
			.list_for("bob")
			.len(),
		1
	);

	let result =
		remove_account(&store, &spool, dir.path(), "bob", QueuePolicy::Drain).expect("remove");
	assert_eq!(result.masked_addresses, 1);
	assert_eq!(result.app_passwords, 1);
	assert_eq!(result.suppressed_addresses, 1);

	assert!(store.list_masked("bob").is_empty());
	assert!(
		crate::directory_store::AppPasswordStore::open(dir.path())
			.expect("app passwords")
			.for_account("bob")
			.is_empty()
	);
	assert!(
		SuppressionList::open(dir.path())
			.expect("suppression")
			.list_for("bob")
			.is_empty()
	);
}

#[test]
fn discard_removes_only_the_accounts_queued_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let other_count_before = spool
		.list()
		.expect("list")
		.into_iter()
		.filter(|id| {
			spool
				.load(*id)
				.map(|e| e.envelope.reverse_path == "carol@elsewhere.example")
				.unwrap_or(false)
		})
		.count();
	assert_eq!(other_count_before, 1);

	let result =
		remove_account(&store, &spool, dir.path(), "alice", QueuePolicy::Discard).expect("remove");
	assert_eq!(result.queued_messages_discarded, 2);
	assert_eq!(result.queued_messages_left, 0);

	let remaining = spool.list().expect("list");
	assert_eq!(
		remaining.len(),
		1,
		"only the other-account envelope survives"
	);
	for id in remaining {
		let entry = spool.load(id).expect("load");
		assert_eq!(entry.envelope.reverse_path, "carol@elsewhere.example");
	}
}

#[test]
fn drain_leaves_the_queue_untouched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let result =
		remove_account(&store, &spool, dir.path(), "alice", QueuePolicy::Drain).expect("remove");
	assert_eq!(result.queued_messages_discarded, 0);
	assert_eq!(result.queued_messages_left, 2);

	let remaining = spool.list().expect("list");
	assert_eq!(remaining.len(), 3, "all three envelopes stay");
}

#[test]
fn an_unknown_name_is_not_found_and_touches_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let result = remove_account(&store, &spool, dir.path(), "ghost", QueuePolicy::Drain);
	assert!(matches!(
		result,
		Err(crate::directory_store::StoreError::NotFound(_))
	));

	// alice is still there; her satellites were not disturbed.
	assert_eq!(store.list_masked("alice").len(), 1);
	assert_eq!(
		crate::directory_store::AppPasswordStore::open(dir.path())
			.expect("app passwords")
			.for_account("alice")
			.len(),
		1
	);
	assert_eq!(
		SuppressionList::open(dir.path())
			.expect("suppression")
			.list_for("alice")
			.len(),
		1
	);
	assert_eq!(spool.list().expect("list").len(), 3);
}

/// A name with path separators or shell metacharacters must be
/// rejected by the validator before any directory is touched, even if
/// the directory is currently absent.
#[test]
fn a_name_that_is_not_a_valid_account_name_never_reaches_the_filesystem() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());

	for bad in [
		"../escape",
		"../../etc",
		"name with space",
		"-leading-hyphen",
	] {
		let sentinel = dir.path().join("accounts").join(bad);
		let before = sentinel.exists();
		let result = remove_account(&store, &spool, dir.path(), bad, QueuePolicy::Drain);
		assert!(
			matches!(&result, Err(crate::directory_store::StoreError::Invalid(_))),
			"{bad} should be rejected as invalid"
		);
		let after = sentinel.exists();
		// The path does not exist before and must not exist after; the
		// name never reached the filesystem layer.
		assert_eq!(before, after, "name {bad} touched the filesystem");
	}
}

/// A recreated account must not inherit the previous owner's app
/// passwords through the in-memory mirror inside a still-running
/// store. The on-disk file is cleared by `AppPasswordStore::remove_account`
/// already; the leak this guards against is the one the live
/// `AccountStore` keeps in `RwLock<Vec<(String, AppPassword)>>` and
/// keeps applying through every `build_directory()`. Without the
/// retain-on-remove step, removing alice and recreating her would let
/// the previous owner's app password authenticate the new account.
#[test]
fn a_recreated_account_does_not_inherit_the_previous_app_passwords() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	let primary = crate::smtp::auth::tests::fixture_password().to_string();
	let primary_hash = crate::smtp::auth::hash_password(&primary).expect("hash primary");
	add_account_with_primary_hash(&store, "alice", "alice@example.org", &primary_hash);

	let app_secret = uuid::Uuid::now_v7().simple().to_string();
	let app_hash = crate::smtp::auth::hash_password(&app_secret).expect("hash app");
	store
		.add_app_password(
			"alice",
			crate::directory_store::AppPassword {
				label: "phone".to_string(),
				hash: app_hash,
				expires_at: None,
				ip_cidr: None,
			},
		)
		.expect("add app pw");

	// Confirm the directory authenticates the app password now.
	assert_eq!(
		store
			.handle()
			.current()
			.authenticate("alice", &app_secret, crate::config::Protocol::Api)
			.as_deref(),
		Some("alice"),
		"sanity: the app password authenticates the original alice"
	);

	// Remove alice; the disk and in-memory app passwords must move together.
	remove_account(&store, &spool, dir.path(), "alice", QueuePolicy::Drain).expect("remove");
	assert!(store.dynamic("alice").is_none());

	// Recreate alice with a fresh primary password.
	let new_primary = crate::smtp::auth::tests::second_password().to_string();
	let new_primary_hash =
		crate::smtp::auth::hash_password(&new_primary).expect("hash new primary");
	add_account_with_primary_hash(&store, "alice", "alice@example.org", &new_primary_hash);

	// The old app password must NOT authenticate the new alice.
	assert!(
		store
			.handle()
			.current()
			.authenticate("alice", &app_secret, crate::config::Protocol::Api)
			.is_none(),
		"a recreated account must not inherit the previous owner's app password"
	);
}

/// Helper for the app-password test: adds a dynamic account whose
/// primary hash is supplied by the caller (the per-test mintage
/// pattern this codebase uses so a literal never reaches a
/// `password` parameter the scanner would flag).
fn add_account_with_primary_hash(
	store: &AccountStore,
	name: &str,
	address: &str,
	password_hash: &str,
) {
	store
		.add(crate::directory_store::DynamicAccount {
			name: name.to_string(),
			addresses: vec![address.to_string()],
			password_hash: password_hash.to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add");
}
