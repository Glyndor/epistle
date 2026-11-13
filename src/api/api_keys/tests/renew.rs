//! `renew` swaps the secret and the expiry in one write and leaves the rest of
//! the key alone.

use super::*;

fn stored(dir: &std::path::Path) -> ApiKeyStore {
	ApiKeyStore::open(dir).expect("open")
}

fn add(dir: &std::path::Path, expires_at: Option<u64>) {
	let mut store = stored(dir);
	store
		.add(ApiKey {
			label: "panel".to_string(),
			hash: sha256_hash("old"),
			expires_at,
			ip_cidr: Some("203.0.113.0/24".to_string()),
			scopes: vec!["read".to_string(), "write".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add");
}

#[test]
fn renew_replaces_the_secret_and_the_expiry_and_nothing_else() {
	let dir = tempfile::tempdir().expect("tempdir");
	add(dir.path(), Some(100));
	let mut store = stored(dir.path());
	store
		.renew("panel", sha256_hash("new"), 9_000)
		.expect("renew");
	let key = stored(dir.path()).keys()[0].clone();
	assert_eq!(key.hash, sha256_hash("new"));
	assert_eq!(key.expires_at, Some(9_000));
	assert_eq!(key.ip_cidr.as_deref(), Some("203.0.113.0/24"));
	assert_eq!(key.scopes, ["read", "write"]);
}

#[test]
fn renew_gives_a_key_that_never_expired_a_deadline() {
	let dir = tempfile::tempdir().expect("tempdir");
	add(dir.path(), None);
	stored(dir.path())
		.renew("panel", sha256_hash("new"), 77)
		.expect("renew");
	assert_eq!(stored(dir.path()).keys()[0].expires_at, Some(77));
}

#[test]
fn rotate_keeps_the_expiry_that_renew_would_replace() {
	let dir = tempfile::tempdir().expect("tempdir");
	add(dir.path(), Some(100));
	stored(dir.path())
		.rotate("panel", sha256_hash("new"))
		.expect("rotate");
	assert_eq!(stored(dir.path()).keys()[0].expires_at, Some(100));
}

#[test]
fn renew_of_a_label_that_is_not_there_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let error = stored(dir.path())
		.renew("panel", sha256_hash("new"), 1)
		.expect_err("absent");
	assert!(
		error.to_string().contains("no such API key \"panel\""),
		"{error}"
	);
}
