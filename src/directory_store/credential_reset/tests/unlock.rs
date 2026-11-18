//! Only an administrator unlocks a reset account: a new password, and a new
//! second factor where it had one. A replacement of the whole record that
//! does not settle them unlocks nothing.

use super::fixture::*;
use crate::config::Protocol;
use crate::directory_store::{CredentialReset, NewPassword};
use crate::test_support::fixtures;

fn reset(store: &crate::directory_store::AccountStore, name: &str) {
	store
		.reset_credentials(&targets(store, &[name]), &placeholder())
		.expect("reset");
}

fn hash(password: &str) -> String {
	crate::smtp::auth::tests::base::hash(password)
}

#[test]
fn a_new_password_unlocks_an_account_that_had_no_second_factor() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	reset(&store, WITHOUT_FACTOR);
	store
		.set_password_hash(WITHOUT_FACTOR, hash(fixtures::second_password()), None)
		.expect("new password");
	assert_eq!(store.dynamic_account(WITHOUT_FACTOR).unwrap().reset, None);
	assert!(!store.is_locked(WITHOUT_FACTOR));
	let directory = store.handle().current();
	assert_eq!(
		directory.authenticate(WITHOUT_FACTOR, fixtures::second_password(), Protocol::Imaps),
		Some(WITHOUT_FACTOR.to_string())
	);
	assert_eq!(
		directory.authenticate(WITHOUT_FACTOR, fixtures::password(), Protocol::Imaps),
		None,
		"the old password came back"
	);
}

#[test]
fn an_account_that_had_a_second_factor_needs_a_new_one_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	reset(&store, WITH_FACTOR);
	store
		.set_password_hash(WITH_FACTOR, hash(fixtures::second_password()), None)
		.expect("new password");
	assert_eq!(
		store.dynamic_account(WITH_FACTOR).unwrap().reset,
		Some(CredentialReset {
			password: false,
			second_factor: true
		})
	);
	assert_eq!(
		store.handle().current().authenticate(
			WITH_FACTOR,
			fixtures::second_password(),
			Protocol::Imaps
		),
		None,
		"a password alone unlocked an account that had a second factor"
	);
	let secret = crate::totp::encode_base32(&[9u8; 20]);
	store
		.set_totp(WITH_FACTOR, Some(secret.clone()))
		.expect("enrol");
	assert_eq!(store.dynamic_account(WITH_FACTOR).unwrap().reset, None);
	let with_code = format!("{}{}", fixtures::second_password(), totp_code(&secret));
	assert_eq!(
		store
			.handle()
			.current()
			.authenticate(WITH_FACTOR, &with_code, Protocol::Imaps),
		Some(WITH_FACTOR.to_string())
	);
}

#[test]
fn removing_the_second_factor_on_purpose_also_settles_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	reset(&store, WITH_FACTOR);
	store.set_totp(WITH_FACTOR, None).expect("remove");
	assert!(store.is_locked(WITH_FACTOR), "the password is still to set");
	store
		.set_password_hash(WITH_FACTOR, hash(fixtures::second_password()), None)
		.expect("new password");
	assert!(!store.is_locked(WITH_FACTOR));
}

#[test]
fn a_replacement_without_a_new_password_keeps_the_account_locked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	reset(&store, WITHOUT_FACTOR);
	let mut replacement = store.dynamic_account(WITHOUT_FACTOR).unwrap();
	replacement.reset = None;
	replacement.display_name = Some("Bob".to_string());
	store
		.replace_account(WITHOUT_FACTOR, replacement, None)
		.expect("replace");
	assert!(
		store.is_locked(WITHOUT_FACTOR),
		"a PUT unlocked the account"
	);
	let replacement = store.dynamic_account(WITHOUT_FACTOR).unwrap();
	let new_password = NewPassword {
		hash: hash(fixtures::second_password()),
		scram: None,
	};
	store
		.replace_account(WITHOUT_FACTOR, replacement, Some(new_password))
		.expect("replace");
	assert!(!store.is_locked(WITHOUT_FACTOR));
}

#[test]
fn a_replacement_built_before_the_reset_neither_unlocks_nor_restores_the_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	// Read before the reset, written after it, as a `PUT` racing the
	// rotation would.
	let mut stale = store.dynamic_account(WITH_FACTOR).unwrap();
	reset(&store, WITH_FACTOR);
	let locked = store.dynamic_account(WITH_FACTOR).unwrap();
	stale.display_name = Some("Alice".to_string());
	store
		.replace_account(WITH_FACTOR, stale, None)
		.expect("replace");
	let account = store.dynamic_account(WITH_FACTOR).unwrap();
	assert_eq!(account.reset, locked.reset, "the reset was settled");
	assert_eq!(
		account.password_hash, locked.password_hash,
		"the old password came back"
	);
	assert!(
		account.totp_secret.is_none(),
		"the old TOTP secret came back"
	);
	assert_eq!(account.display_name.as_deref(), Some("Alice"));
	assert_eq!(
		store
			.handle()
			.current()
			.authenticate(WITH_FACTOR, fixtures::password(), Protocol::Imaps),
		None
	);
}
