//! What the file is asked again under its lock: the key that asks for a write
//! still has to be there and still reach that far.

use std::io::ErrorKind;

use super::super::*;
use crate::api::api_keys::{ApiKey, ApiKeyStore, sha256_hash};

fn key(label: &str, scopes: &[&str], domain: &str) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: sha256_hash(label),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
		grants: Vec::new(),
		domains: vec![domain.to_string()],
		account: None,
		auto_submitted: false,
	}
}

fn maker() -> ApiKey {
	key("maker", &["key", "read"], "a.example")
}

/// The maker as the request saw it.
fn asked_as(maker: &ApiKey) -> Caller {
	Caller::new(
		Reach::of_key(maker, None),
		maker.label.clone(),
		maker.hash.clone(),
	)
}

/// What the file may hold by the time the write is made: each leaves the maker
/// unable to make the key it was about to.
fn changed() -> Vec<(&'static str, Option<ApiKey>)> {
	let mut expired = maker();
	expired.expires_at = Some(1);
	let mut bound = maker();
	bound.account = Some("ann".to_string());
	vec![
		("gone", None),
		(
			"moved to another domain",
			Some(key("maker", &["key", "read"], "b.example")),
		),
		(
			"no longer a maker",
			Some(key("maker", &["read"], "a.example")),
		),
		(
			"fewer scopes",
			Some(key("maker", &["key", "manage:read"], "a.example")),
		),
		("expired", Some(expired)),
		("bound to an account", Some(bound)),
	]
}

fn store_with(keys: Vec<ApiKey>) -> (tempfile::TempDir, ApiKeyStore) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	for key in keys {
		store.add(key).expect("add");
	}
	(dir, store)
}

fn labels(dir: &tempfile::TempDir) -> Vec<String> {
	let store = ApiKeyStore::open(dir.path()).expect("open");
	store.keys().iter().map(|key| key.label.clone()).collect()
}

#[test]
fn a_new_key_is_written_only_while_the_maker_still_reaches_that_far() {
	let before = maker();
	let caller = asked_as(&before);
	let child = key("child", &["read"], "a.example");
	let wanted = Reach::of_key(&child, None);
	let ask = Ask {
		caller: &caller,
		wanted: &wanted,
		max_keys: MAX_KEYS_BY_KEY,
	};
	let (dir, mut store) = store_with(vec![before.clone()]);
	store.add_by(child.clone(), None, ask).expect("unchanged");
	assert_eq!(labels(&dir), ["maker", "child"]);
	for (what, now) in changed() {
		let (dir, mut store) = store_with(now.into_iter().collect());
		let refused = store.add_by(child.clone(), None, ask).expect_err(what);
		assert_eq!(refused.kind(), ErrorKind::PermissionDenied, "{what}");
		assert!(!labels(&dir).contains(&"child".to_string()), "{what}");
	}
}

#[test]
fn a_key_is_revoked_only_by_what_the_maker_reaches_now() {
	let before = maker();
	let caller = asked_as(&before);
	let other = key("other", &["read"], "a.example");
	let within = |own: &Reach, held: &ApiKey| own.covers(&Reach::of_key(held, None)).is_ok();
	let (dir, mut store) = store_with(vec![before.clone(), other.clone()]);
	store
		.remove_by("other", &caller, within)
		.expect("unchanged");
	assert_eq!(labels(&dir), ["maker"]);
	for (what, now) in changed() {
		let mut keys: Vec<ApiKey> = now.into_iter().collect();
		keys.push(other.clone());
		let (dir, mut store) = store_with(keys);
		let refused = store.remove_by("other", &caller, within).expect_err(what);
		assert!(
			matches!(
				refused.kind(),
				ErrorKind::PermissionDenied | ErrorKind::NotFound
			),
			"{what}: {refused}"
		);
		assert!(labels(&dir).contains(&"other".to_string()), "{what}");
	}
}
