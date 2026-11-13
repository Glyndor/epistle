//! Queue policy on removal, and names that never reach the filesystem.

use crate::directory_store::removal::{QueuePolicy, remove_account};
use crate::queue::SuppressionList;

use super::base::*;

#[tokio::test]
async fn discard_removes_only_the_accounts_queued_messages() {
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

	let result = remove_account(
		&store,
		&spool,
		dir.path(),
		"alice",
		QueuePolicy::Discard,
		None,
	)
	.await
	.expect("remove");
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

#[tokio::test]
async fn drain_leaves_the_queue_untouched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

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
	assert_eq!(result.queued_messages_discarded, 0);
	assert_eq!(result.queued_messages_left, 2);

	let remaining = spool.list().expect("list");
	assert_eq!(remaining.len(), 3, "all three envelopes stay");
}

#[tokio::test]
async fn an_unknown_name_is_not_found_and_touches_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "alice");

	let result = remove_account(
		&store,
		&spool,
		dir.path(),
		"ghost",
		QueuePolicy::Drain,
		None,
	)
	.await;
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
#[tokio::test]
async fn a_name_that_is_not_a_valid_account_name_never_reaches_the_filesystem() {
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
		let result =
			remove_account(&store, &spool, dir.path(), bad, QueuePolicy::Drain, None).await;
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
