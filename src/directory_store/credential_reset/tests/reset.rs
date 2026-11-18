//! What a reset leaves on disk, and what the directory then refuses.

use super::fixture::*;
use crate::config::Protocol;
use crate::directory_store::CredentialReset;
use crate::smtp::directory::gate_fixture::every_protocol;
use crate::test_support::fixtures;

#[test]
fn a_reset_drops_every_credential_and_records_what_is_left() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let placeholder = placeholder();
	let reset = store
		.reset_credentials(
			&targets(&store, &[WITH_FACTOR, WITHOUT_FACTOR]),
			&placeholder,
		)
		.expect("reset");
	assert_eq!(reset, [WITH_FACTOR, WITHOUT_FACTOR]);
	for (name, second_factor) in [(WITH_FACTOR, true), (WITHOUT_FACTOR, false)] {
		// Read back from disk, not from the store that wrote it.
		let reread = crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("reopen");
		let account = reread.dynamic_account(name).expect(name);
		assert_eq!(
			account.reset,
			Some(CredentialReset {
				password: true,
				second_factor
			}),
			"{name}"
		);
		assert_eq!(account.password_hash, placeholder, "{name}");
		assert!(
			!crate::smtp::auth::verify_password(&account.password_hash, fixtures::password()),
			"the old password of {name} still verifies"
		);
		assert!(account.scram.is_none(), "{name} kept its SCRAM verifier");
		assert!(account.totp_secret.is_none(), "{name} kept its TOTP secret");
		assert!(reread.is_locked(name));
	}
	let untouched = store.dynamic_account(UNTOUCHED).expect("carol");
	assert_eq!(untouched.reset, None);
	assert!(untouched.scram.is_some());
	assert!(!store.is_locked(UNTOUCHED));
}

#[test]
fn a_reset_account_signs_in_on_no_protocol_and_the_others_still_do() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	store
		.reset_credentials(&targets(&store, &[WITHOUT_FACTOR]), &placeholder())
		.expect("reset");
	let directory = store.handle().current();
	for protocol in every_protocol() {
		assert_eq!(
			directory.authenticate(WITHOUT_FACTOR, fixtures::password(), protocol),
			None,
			"{protocol:?}"
		);
	}
	assert_eq!(
		directory.authenticate(UNTOUCHED, fixtures::password(), Protocol::Imaps),
		Some(UNTOUCHED.to_string())
	);
	assert!(directory.awaits_credential_reset(WITHOUT_FACTOR));
	assert!(!directory.awaits_credential_reset(UNTOUCHED));
}

#[test]
fn an_account_whose_password_changed_since_the_decision_is_left_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let decided = targets(&store, &[WITHOUT_FACTOR]);
	let fresh = crate::smtp::auth::tests::base::hash(fixtures::second_password());
	store
		.set_password_hash(WITHOUT_FACTOR, fresh.clone(), None)
		.expect("new password");
	let reset = store
		.reset_credentials(&decided, &placeholder())
		.expect("reset");
	assert!(reset.is_empty());
	let account = store.dynamic_account(WITHOUT_FACTOR).expect("bob");
	assert_eq!(account.password_hash, fresh);
	assert_eq!(account.reset, None);
}

#[test]
fn a_target_that_is_gone_is_skipped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let mut decided = targets(&store, &[WITHOUT_FACTOR]);
	decided.insert(
		0,
		crate::directory_store::ResetTarget {
			name: "ghost".to_string(),
			digest: "00".to_string(),
		},
	);
	let reset = store
		.reset_credentials(&decided, &placeholder())
		.expect("reset");
	assert_eq!(reset, [WITHOUT_FACTOR]);
	assert!(
		store
			.handle()
			.current()
			.authenticate(UNTOUCHED, fixtures::password(), Protocol::Imaps)
			.is_some()
	);
}
