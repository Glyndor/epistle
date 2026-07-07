//! Tests for the management API key store and per-key admission.

use super::*;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

fn key(label: &str, secret: &str) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
	}
}

#[test]
fn valid_key_admitted() {
	let k = key("ci", "supersecret");
	assert!(k.admits("supersecret", None, 1000));
}

#[test]
fn wrong_key_rejected() {
	let k = key("ci", "supersecret");
	assert!(!k.admits("wrong", None, 1000));
}

#[test]
fn expired_key_rejected() {
	let mut k = key("ci", "supersecret");
	k.expires_at = Some(2000);
	assert!(k.admits("supersecret", None, 1999));
	assert!(!k.admits("supersecret", None, 2000));
}

#[test]
fn ip_mismatch_rejected_match_accepted() {
	let mut k = key("ci", "supersecret");
	k.ip_cidr = Some("10.0.0.0/8".to_string());
	assert!(k.admits("supersecret", Some(ip("10.1.2.3")), 1000));
	assert!(!k.admits("supersecret", Some(ip("11.0.0.1")), 1000));
	// A CIDR with no client IP cannot be satisfied.
	assert!(!k.admits("supersecret", None, 1000));
}

#[test]
fn malformed_cidr_rejected() {
	let mut k = key("ci", "supersecret");
	k.ip_cidr = Some("nonsense".to_string());
	assert!(!k.admits("supersecret", Some(ip("10.1.2.3")), 1000));
}

#[test]
fn sha256_token_matches_is_correct() {
	let stored = sha256_hash("hunter2");
	assert!(sha256_token_matches(&stored, "hunter2"));
	assert!(!sha256_token_matches(&stored, "hunter3"));
	// A non-sha256 stored value never matches here.
	assert!(!sha256_token_matches("argon2:whatever", "hunter2"));
}

#[test]
fn store_add_list_remove_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	store.add(key("ci", "secret1")).expect("add");
	store.add(key("backup", "secret2")).expect("add");

	let rows = store.list();
	assert_eq!(rows.len(), 2);
	assert!(rows.iter().any(|(l, _, _)| l == "ci"));

	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	assert_eq!(reopened.keys().len(), 2);

	store.remove("ci").expect("remove");
	assert_eq!(store.keys().len(), 1);
	assert!(store.remove("ci").is_err());
}

#[test]
fn add_rejects_duplicate_label_and_bad_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	store.add(key("ci", "secret1")).expect("add");
	assert!(store.add(key("ci", "again")).is_err());
	let mut bad = key("bad", "secret");
	bad.ip_cidr = Some("10.0.0.0/40".to_string());
	assert!(store.add(bad).is_err());
}
