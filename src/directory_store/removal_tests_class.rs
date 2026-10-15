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
