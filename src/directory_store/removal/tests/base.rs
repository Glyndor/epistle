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

/// A 32-byte Bayes key, minted at run time from two UUIDs. The
/// `[0u8; 32]` base is overwritten by the copies, so no literal
/// survives to the `with_key` call; the same idiom the SCRAM salt
/// and TOTP secret tests settled for, extended to 32 bytes the way
/// `src/smtp/server/tests/mods/tests_subjectpass.rs` does.
pub(super) fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

pub(super) const DOMAIN: &str = "example.org";

pub(in super::super) fn store_and_spool(dir: &Path) -> (Arc<AccountStore>, FsSpool) {
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

pub(super) fn enqueue(spool: &FsSpool, reverse_path: &str, body: &str) {
	spool
		.store(
			&AcceptedMessage {
				reverse_path: reverse_path.to_string(),
				recipients: vec!["bob@elsewhere.example".to_string()],
				data: format!("Subject: {body}\r\n\r\n{body}\r\n").into_bytes(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
}

pub(super) fn add_account(store: &AccountStore, name: &str, address: &str) {
	store
		.add(crate::directory_store::DynamicAccount {
			name: name.to_string(),
			addresses: vec![address.to_string()],
			password_hash: "$argon2id$placeholder".to_string(),
			..crate::directory_store::DynamicAccount::default()
		})
		.expect("add");
}

/// Seed every footprint an account leaves: two messages in the
/// mailbox, one masked address, one app password, one suppressed
/// recipient, plus two queued messages from the account's reverse
/// path and one from a different account.
pub(in super::super) fn seed(dir: &Path, store: &Arc<AccountStore>, spool: &FsSpool, name: &str) {
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
				save_sent: None,
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

#[tokio::test]
async fn removing_an_account_deletes_its_mailbox_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let mailbox_root = dir.path().join("accounts/alice");
	assert!(mailbox_root.join("new/first.eml").exists());

	let result = remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("remove");

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

#[tokio::test]
async fn recreating_the_name_starts_from_an_empty_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "victim");

	remove_account(
		&store,
		&spool,
		dir.path(),
		"victim",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("remove");
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

#[tokio::test]
async fn removing_an_account_drops_its_masked_addresses_app_passwords_and_suppressions() {
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

	let result = remove_account(&store, &spool, dir.path(), "bob", QueuePolicy::Drain, None)
		.await
		.expect("remove");
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
