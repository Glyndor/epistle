//! Removal clears ban rows and aborts when the corpus cannot be forgotten.

use std::sync::Arc;

use crate::directory_store::AccountStore;
use crate::directory_store::removal::{QueuePolicy, remove_account};
use crate::storage::FsSpool;

use super::base::*;

/// A recreated account must not inherit the previous owner's app
/// passwords through the in-memory mirror inside a still-running
/// store. The on-disk file is cleared by `AppPasswordStore::remove_account`
/// already; the leak this guards against is the one the live
/// `AccountStore` keeps in `RwLock<Vec<(String, AppPassword)>>` and
/// keeps applying through every `build_directory()`. Without the
/// retain-on-remove step, removing alice and recreating her would let
/// the previous owner's app password authenticate the new account.
#[tokio::test]
async fn a_recreated_account_does_not_inherit_the_previous_app_passwords() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	let primary = crate::smtp::auth::tests::base::fixture_password().to_string();
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
				save_sent: None,
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
	remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("remove");
	assert!(store.dynamic("alice").is_none());

	// Recreate alice with a fresh primary password.
	let new_primary = crate::smtp::auth::tests::base::second_password().to_string();
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
			..crate::directory_store::DynamicAccount::default()
		})
		.expect("add");
}

/// A removed account's ban rows go with it, and the clearing runs on the
/// caller's runtime. `#[tokio::test]` puts the call inside a runtime
/// worker, the position both API handlers call from, so a `block_on`
/// in the removal path panics here instead of in production.
#[tokio::test]
async fn removing_an_account_clears_its_ban_rows_and_leaves_other_accounts_banned() {
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy, BanStore, subject_account};

	let dir = tempfile::tempdir().expect("tempdir");
	let bans = FakeBanStore::new(BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60 * 60,
		known_network_max_per_account: 32,
	});
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			vec![DOMAIN.to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store")
		.with_ban_store(Arc::new(bans.clone())),
	);
	let spool = FsSpool::open(dir.path()).expect("open spool");
	add_account(&store, "alice", "alice@example.org");
	add_account(&store, "bob", "bob@example.org");
	let now: u64 = 1_700_000_000;
	for name in ["alice", "bob"] {
		bans.arm_ban(
			&subject_account(name),
			BanInfo {
				until_secs: now + 600,
				reason: "armed by the test".to_string(),
			},
		);
	}

	remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("remove");

	assert_eq!(bans.call_count("remove_account"), 1);
	assert!(
		bans.is_banned(&subject_account("alice"), now)
			.await
			.is_none(),
		"the removed account's ban must not survive for a recreated name"
	);
	assert!(
		bans.is_banned(&subject_account("bob"), now).await.is_some(),
		"another account's ban is not this removal's to clear"
	);
}

/// `BayesStore::forget_scope` failing must abort the account removal
/// so a recreated account does not inherit the previous owner's
/// training rows. The lazy pool below cannot acquire a connection, so
/// `forget_scope` returns an error; `remove_account` propagates that
/// as `StoreError::BayesPurge` and the dynamic-account row stays on
/// disk for the operator to retry.
///
/// The retry half of the test re-runs `remove_account` against the
/// same account with `bayes: None`. By the time the first call
/// aborted, the mailbox, satellites and queue were already gone, so
/// the second call must succeed, drop the dynamic-account row, and
/// return counts that reflect an empty footprint rather than error
/// when the cleanup steps find nothing left to clean. Without the
/// guarantee that the second call succeeds, the `BayesPurge` abort
/// buys the operator nothing: a recreated account after a transient
/// bayes failure would still inherit the missing corpus the retry
/// could not finish.
#[tokio::test]
async fn forgetting_the_corpus_failing_aborts_account_removal() {
	use crate::antispam::corpus::BayesStore;

	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	add_account(&store, "alice", "alice@example.org");

	let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
		.expect("lazy pool never connects");
	let bayes = BayesStore::with_key(pool, fixture_key());

	let result = remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		Some(&bayes),
	)
	.await;
	let error = result.expect_err("removal must abort when the corpus purge fails");
	assert!(
		matches!(error, crate::directory_store::StoreError::BayesPurge { ref account, .. } if account == "alice"),
		"got {error:?}"
	);

	// The account row survives: a retry can drop the corpus rows and
	// finish the removal without recreating a new account that would
	// inherit the stale scope.
	let reread = AccountStore::open(
		dir.path(),
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen store");
	assert!(
		reread.dynamic("alice").is_some(),
		"the account row must survive when the corpus purge aborts"
	);

	// Retry: with no bayes store, the cleanup steps are idempotent
	// (every footprint from the aborted call was already gone), the
	// dynamic-account row drops, and the counts come back at zero
	// rather than erroring on absent state. The fresh `AccountStore`
	// below is the same instance the production retry would see
	// (the in-memory mirror of a still-running process sees the same
	// state because the aborted call never reached `store.remove`).
	let retry = remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("retry without a bayes store must succeed");
	assert_eq!(
		retry.mailbox_files, 0,
		"the retry must not error on the absent mailbox"
	);
	assert_eq!(retry.masked_addresses, 0);
	assert_eq!(retry.app_passwords, 0);
	assert_eq!(retry.suppressed_addresses, 0);
	assert_eq!(retry.correspondent_addresses, 0);
	assert_eq!(retry.queued_messages_discarded, 0);
	assert_eq!(retry.queued_messages_left, 0);
	assert_eq!(retry.bayes_tokens_removed, 0);

	let reread = AccountStore::open(
		dir.path(),
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen store");
	assert!(
		reread.dynamic("alice").is_none(),
		"the dynamic-account row must be gone after the retry"
	);
}
