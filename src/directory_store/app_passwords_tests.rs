//! Tests for the app-password store and per-credential admission.

use super::*;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

fn app_password(label: &str, secret: &str) -> AppPassword {
	AppPassword {
		label: label.to_string(),
		hash: crate::smtp::auth::tests::hash(secret),
		expires_at: None,
		ip_cidr: None,
	}
}

#[test]
fn valid_secret_admitted() {
	let pw = app_password("phone", "correct-secret");
	assert!(pw.admits("correct-secret", None, 1000));
}

#[test]
fn wrong_secret_rejected() {
	let pw = app_password("phone", "correct-secret");
	assert!(!pw.admits("wrong-secret", None, 1000));
}

#[test]
fn expired_rejected_unexpired_accepted() {
	let mut pw = app_password("phone", "secret");
	pw.expires_at = Some(2000);
	assert!(pw.admits("secret", None, 1999));
	assert!(!pw.admits("secret", None, 2000));
	assert!(!pw.admits("secret", None, 2001));
}

#[test]
fn ip_inside_cidr_accepted_outside_rejected() {
	let mut pw = app_password("phone", "secret");
	pw.ip_cidr = Some("203.0.113.0/24".to_string());
	assert!(pw.admits("secret", Some(ip("203.0.113.5")), 1000));
	assert!(!pw.admits("secret", Some(ip("203.0.114.5")), 1000));
}

#[test]
fn cidr_with_unknown_ip_rejected() {
	let mut pw = app_password("phone", "secret");
	pw.ip_cidr = Some("203.0.113.0/24".to_string());
	// A configured allowlist cannot be satisfied without a client IP.
	assert!(!pw.admits("secret", None, 1000));
}

#[test]
fn malformed_cidr_rejected() {
	let mut pw = app_password("phone", "secret");
	pw.ip_cidr = Some("not-a-cidr".to_string());
	assert!(!pw.admits("secret", Some(ip("203.0.113.5")), 1000));
}

#[test]
fn store_add_list_remove_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = AppPasswordStore::open(dir.path()).expect("open");
	store
		.add("alice", app_password("phone", "secret"))
		.expect("add");
	store
		.add("alice", app_password("laptop", "other"))
		.expect("add");

	let rows = store.list();
	assert_eq!(rows.len(), 2);
	assert!(rows.iter().any(|(a, l, _, _)| a == "alice" && l == "phone"));

	// Reopen to confirm persistence.
	let reopened = AppPasswordStore::open(dir.path()).expect("reopen");
	assert_eq!(reopened.for_account("alice").len(), 2);

	store.remove("alice", "phone").expect("remove");
	assert_eq!(store.for_account("alice").len(), 1);
	assert!(matches!(
		store.remove("alice", "phone"),
		Err(StoreError::NotFound(_))
	));
}

#[test]
fn add_rejects_duplicate_label_and_bad_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = AppPasswordStore::open(dir.path()).expect("open");
	store
		.add("alice", app_password("phone", "secret"))
		.expect("add");
	assert!(matches!(
		store.add("alice", app_password("phone", "again")),
		Err(StoreError::Duplicate(_))
	));
	let mut bad = app_password("bad", "secret");
	bad.ip_cidr = Some("999.0.0.0/8".to_string());
	assert!(matches!(
		store.add("alice", bad),
		Err(StoreError::Invalid(_))
	));
}

#[test]
fn account_lookup_is_case_insensitive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = AppPasswordStore::open(dir.path()).expect("open");
	store
		.add("Alice", app_password("phone", "secret"))
		.expect("add");
	assert_eq!(store.for_account("alice").len(), 1);
	assert_eq!(store.for_account("ALICE").len(), 1);
}
