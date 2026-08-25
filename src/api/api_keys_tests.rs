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
		// `add()` rejects empty scopes, so every test-built key carries one.
		scopes: vec![Scope::Read.as_str().to_string()],
	}
}

#[test]
fn valid_key_admitted() {
	let k = key("ci", "supersecret");
	assert!(k.admits_any("supersecret", None, 1000, &[Scope::Read]));
}

#[test]
fn wrong_key_rejected() {
	let k = key("ci", "supersecret");
	assert!(!k.admits_any("wrong", None, 1000, &[Scope::Read]));
}

#[test]
fn expired_key_rejected() {
	let mut k = key("ci", "supersecret");
	k.expires_at = Some(2000);
	assert!(k.admits_any("supersecret", None, 1999, &[Scope::Read]));
	assert!(!k.admits_any("supersecret", None, 2000, &[Scope::Read]));
}

#[test]
fn ip_mismatch_rejected_match_accepted() {
	let mut k = key("ci", "supersecret");
	k.ip_cidr = Some("10.0.0.0/8".to_string());
	assert!(k.admits_any("supersecret", Some(ip("10.1.2.3")), 1000, &[Scope::Read]));
	assert!(!k.admits_any("supersecret", Some(ip("11.0.0.1")), 1000, &[Scope::Read]));
	// A CIDR with no client IP cannot be satisfied.
	assert!(!k.admits_any("supersecret", None, 1000, &[Scope::Read]));
}

#[test]
fn malformed_cidr_rejected() {
	let mut k = key("ci", "supersecret");
	k.ip_cidr = Some("nonsense".to_string());
	assert!(!k.admits_any("supersecret", Some(ip("10.1.2.3")), 1000, &[Scope::Read]));
}

/// A read-scoped key cannot perform a write — the whole point of scopes.
#[test]
fn write_scope_rejected_for_read_only_key() {
	let mut k = key("ci", "supersecret");
	k.scopes = vec!["read".to_string()];
	assert!(k.admits_any("supersecret", None, 1000, &[Scope::Read]));
	assert!(!k.admits_any("supersecret", None, 1000, &[Scope::Write]));
	assert!(!k.admits_any("supersecret", None, 1000, &[Scope::Send]));
}

/// A write scope does NOT imply read or send. Each scope is independent; an
/// operator who wants all three lists them explicitly.
#[test]
fn write_scope_does_not_imply_read_or_send() {
	let mut k = key("ci", "supersecret");
	k.scopes = vec!["write".to_string()];
	assert!(!k.admits_any("supersecret", None, 1000, &[Scope::Read]));
	assert!(k.admits_any("supersecret", None, 1000, &[Scope::Write]));
	assert!(!k.admits_any("supersecret", None, 1000, &[Scope::Send]));
}

/// `admits_any` accepts a key that lists ANY of the requested scopes —
/// used by the middleware when the coarse path/method inference is
/// ambiguous (`POST /jmap/api` accepts any of Read/Write/Send; the
/// dispatcher tightens).
#[test]
fn admits_any_against_multi_scope_slice() {
	let mut write_only = key("ci", "supersecret");
	write_only.scopes = vec!["write".to_string()];
	let set = [Scope::Read, Scope::Write, Scope::Send];
	assert!(write_only.admits_any("supersecret", None, 1000, &set));
}

/// A legacy key (empty `scopes`) still admits every scope — the migration
/// contract: a key installed before the `scopes` field existed must keep
/// authenticating on upgrade. This is the test that proves we do not break
/// existing operators.
#[test]
fn legacy_key_admits_every_scope() {
	let mut k = key("ci", "supersecret");
	k.scopes = Vec::new();
	let set = [Scope::Read, Scope::Write, Scope::Send];
	assert!(
		k.admits_any("supersecret", None, 1000, &set),
		"legacy key must admit any scope"
	);
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
	assert!(rows.iter().any(|row| row.label == "ci"));

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

/// `add()` requires explicit scopes. The CLI is the user-facing gate, but
/// enforcing at the store means no other writer (a future tool, a hand-edited
/// script) can sneak an unscoped key in.
#[test]
fn add_rejects_empty_scopes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	let mut unscoped = key("ci", "secret");
	unscoped.scopes.clear();
	let error = store
		.add(unscoped)
		.expect_err("empty scopes must be rejected");
	assert!(
		error.to_string().contains("scope"),
		"unexpected error message: {error}"
	);
}

/// `add()` rejects unknown scope strings so a typo at creation time is
/// caught immediately rather than silently turning into a 403 at runtime.
#[test]
fn add_rejects_unknown_scope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	let mut bad = key("ci", "secret");
	bad.scopes = vec!["superuser".to_string()];
	assert!(store.add(bad).is_err());
}

/// Loading a pre-existing `api_keys.toml` with an unknown scope string fails
/// closed — the server refuses to start rather than ignore a typo in an
/// operator-edited file.
#[test]
fn open_rejects_unknown_scope_in_existing_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("api_keys.toml");
	std::fs::write(
		&path,
		b"[[keys]]\n\
		  label = \"broken\"\n\
		  hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n\
		  scopes = [\"full-access\"]\n",
	)
	.expect("write fixture");
	assert!(ApiKeyStore::open(dir.path()).is_err());
}

/// Loading a pre-existing `api_keys.toml` with no `scopes` field (legacy)
/// succeeds — that is the migration contract the lot promised.
#[test]
fn open_accepts_legacy_file_without_scopes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("api_keys.toml");
	std::fs::write(
		&path,
		b"[[keys]]\n\
		  label = \"legacy\"\n\
		  hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
	)
	.expect("write fixture");
	let store = ApiKeyStore::open(dir.path()).expect("legacy file must load");
	assert_eq!(store.keys().len(), 1);
	assert!(
		store.keys()[0].scopes.is_empty(),
		"legacy key has empty scopes"
	);
}
