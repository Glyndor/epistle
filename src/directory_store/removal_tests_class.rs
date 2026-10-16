//! A removed account takes its default class with it.

use super::tests::{seed, store_and_spool};
use super::*;
use crate::evidence::MailClass;
use crate::evidence::bindings::{load, update};

#[tokio::test]
async fn a_recreated_name_does_not_inherit_the_default_class() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "notices");
	update(dir.path(), |bindings| {
		bindings
			.accounts
			.insert("notices".into(), MailClass::Transactional);
		bindings
			.accounts
			.insert("other".into(), MailClass::Marketing);
	})
	.expect("bind");
	remove_account(
		&store,
		&spool,
		dir.path(),
		"notices",
		QueuePolicy::Drain,
		None,
	)
	.await
	.expect("remove");
	let left = load(dir.path()).expect("bindings").accounts;
	assert_eq!(left.get("notices"), None, "the class outlived the account");
	assert_eq!(left.get("other"), Some(&MailClass::Marketing));
}

#[tokio::test]
async fn discarding_the_queue_of_a_removed_account_does_not_erase_a_delivery_owed_to_the_evidence()
{
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "notices");
	let id = spool.list().expect("list")[0];
	spool
		.update_envelope(id, |envelope| {
			envelope.reverse_path = "notices@example.org".into();
			envelope
				.outcomes_pending
				.push(crate::storage::PendingOutcome {
					recipient: "ana@remote.example".into(),
					result: crate::evidence::record::OutcomeKind::Delivered,
					attempt: 1,
					remote: None,
					reply: None,
					tls: None,
					dane: false,
					mta_sts: None,
				});
		})
		.expect("pending");
	let result = remove_account(
		&store,
		&spool,
		dir.path(),
		"notices",
		QueuePolicy::Discard,
		None,
	)
	.await;
	assert!(
		result.is_err(),
		"the account was removed with an outcome owed"
	);
	assert!(spool.list().expect("list").contains(&id), "the entry went");
}
