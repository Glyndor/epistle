//! A store with three accounts that share one password: `alice` with a
//! second factor, `bob` without one, and `carol`, whom no reset targets.

use crate::directory_store::{AccountStore, DynamicAccount, ResetTarget};
use crate::smtp::scram::ScramStored;
use crate::test_support::fixtures;

pub(super) const WITH_FACTOR: &str = "alice";
pub(super) const WITHOUT_FACTOR: &str = "bob";
pub(super) const UNTOUCHED: &str = "carol";

/// The TOTP secret of `alice`, base32.
pub(super) fn totp_secret() -> String {
	crate::totp::encode_base32(&[7u8; 20])
}

/// The current code of [`totp_secret`].
pub(super) fn totp_code(secret: &str) -> String {
	let bytes = crate::totp::decode_base32_secret(secret).expect("base32");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0);
	format!("{:06}", crate::totp::totp(&bytes, now))
}

fn account(name: &str, totp: Option<String>) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: crate::smtp::auth::tests::base::hash(fixtures::password()),
		scram: ScramStored::with_fresh_salt(fixtures::password()),
		totp_secret: totp,
		..DynamicAccount::default()
	}
}

/// The store, opened on `dir`.
pub(super) fn store(dir: &std::path::Path) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	store
		.add(account(WITH_FACTOR, Some(totp_secret())))
		.expect("add alice");
	store.add(account(WITHOUT_FACTOR, None)).expect("add bob");
	store.add(account(UNTOUCHED, None)).expect("add carol");
	store
}

/// The reset of `names` as decided now, from the hashes they hold.
pub(super) fn targets(store: &AccountStore, names: &[&str]) -> Vec<ResetTarget> {
	names
		.iter()
		.map(|name| ResetTarget {
			name: name.to_string(),
			digest: crate::directory_store::credential_reset::hash_digest(
				&store.dynamic_account(name).expect(name).password_hash,
			),
		})
		.collect()
}

/// A placeholder hash, of a secret the test throws away.
pub(super) fn placeholder() -> String {
	let secret = crate::queue::srs::generate_secret().expect("random bytes");
	crate::smtp::auth::tests::base::hash(&secret)
}
