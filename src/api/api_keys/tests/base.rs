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
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
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
	let secret = crate::test_support::fixtures::fresh_secret();
	let mut k = key("ci", &secret);
	k.scopes = Vec::new();
	let set = [Scope::Read, Scope::Write, Scope::Send];
	assert!(
		k.admits_any(&secret, None, 1000, &set),
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

/// A key may declare an account and domains at the same time. The two
/// restrictions are not alternatives: the key is confined by both, so it is
/// accepted and kept as it was written.
#[test]
fn a_key_with_an_account_and_domains_is_accepted_and_kept() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	let mut bound = key("ci", "secret1");
	bound.account = Some("alice".to_string());
	bound.domains = vec!["a.example".to_string()];
	store.add(bound).expect("add");

	let row = store
		.list()
		.into_iter()
		.find(|row| row.label == "ci")
		.expect("the key is listed");
	assert_eq!(row.account.as_deref(), Some("alice"));
	assert_eq!(row.domains, vec!["a.example".to_string()]);

	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	let stored = reopened
		.keys()
		.iter()
		.find(|key| key.label == "ci")
		.expect("the key is stored");
	assert_eq!(stored.account.as_deref(), Some("alice"));
	assert_eq!(stored.domains, vec!["a.example".to_string()]);
}

/// The same key, loaded from a file the operator wrote by hand.
#[test]
fn a_key_with_an_account_and_domains_loads_from_a_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("api_keys.toml");
	std::fs::write(
		&path,
		b"[[keys]]\n\
		  label = \"both\"\n\
		  hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n\
		  scopes = [\"read\"]\n\
		  account = \"alice\"\n\
		  domains = [\"a.example\"]\n",
	)
	.expect("write fixture");
	let store = ApiKeyStore::open(dir.path()).expect("the file must load");
	let stored = &store.keys()[0];
	assert_eq!(stored.account.as_deref(), Some("alice"));
	assert_eq!(stored.domains, vec!["a.example".to_string()]);
}

/// The same key, swapped in by the file watcher while the server runs.
#[test]
fn a_key_with_an_account_and_domains_survives_a_reload() {
	let set = ApiKeySet::empty();
	set.reload_from(
		"[[keys]]\n\
		  label = \"both\"\n\
		  hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n\
		  scopes = [\"read\"]\n\
		  account = \"alice\"\n\
		  domains = [\"a.example\"]\n",
	)
	.expect("reload");
	let snapshot = set.snapshot();
	let stored = &snapshot[0];
	assert_eq!(stored.account.as_deref(), Some("alice"));
	assert_eq!(stored.domains, vec!["a.example".to_string()]);
}

/// A secret belongs to one key: adding a second key behind the same secret
/// is refused and leaves the store as it was.
#[test]
fn a_second_key_behind_the_same_secret_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	store.add(key("first", "shared")).expect("add first");
	let error = store
		.add(key("second", "shared"))
		.expect_err("same secret, other label");
	assert!(
		error.to_string().contains("already uses this secret"),
		"{error}"
	);
	assert_eq!(store.keys().len(), 1);
}

const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A key file written before the `auto_submitted` field existed loads with
/// the setting off, in the store and in the summary.
#[test]
fn legacy_key_without_auto_submitted_defaults_to_false() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(
		dir.path().join("api_keys.toml"),
		format!("[[keys]]\nlabel = \"old\"\nhash = \"{ZERO_HASH}\"\nscopes = [\"send\"]\n"),
	)
	.expect("write fixture");
	let store = ApiKeyStore::open(dir.path()).expect("legacy file must load");
	assert!(!store.keys()[0].auto_submitted);
	assert!(!store.list()[0].auto_submitted);
	let set = ApiKeySet::open(dir.path()).expect("legacy file must load in the set");
	assert!(!set.snapshot()[0].auto_submitted);
}

/// The setting is written with the key, survives a reopen and is shown by
/// the summary.
#[test]
fn auto_submitted_is_stored_and_summarized() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	let mut enabled = key("apps", "secret1");
	enabled.auto_submitted = true;
	store.add(enabled).expect("add");
	store.add(key("people", "secret2")).expect("add");

	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	let stored = |label: &str| {
		reopened
			.keys()
			.iter()
			.find(|key| key.label == label)
			.expect("stored")
			.auto_submitted
	};
	assert!(stored("apps"));
	assert!(!stored("people"), "the other key is not touched");
	let listed: Vec<_> = reopened
		.list()
		.into_iter()
		.map(|row| (row.label, row.auto_submitted))
		.collect();
	assert_eq!(
		listed,
		vec![("apps".to_string(), true), ("people".to_string(), false)]
	);
}

/// Changing the setting later rewrites that one field of that one key.
#[test]
fn set_auto_submitted_changes_only_that_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	let mut full = key("apps", "secret1");
	full.expires_at = Some(4_000_000_000);
	full.ip_cidr = Some("10.0.0.0/8".to_string());
	full.scopes = vec!["send".to_string(), "read".to_string()];
	full.domains = vec!["a.example".to_string()];
	full.account = Some("alice".to_string());
	store.add(full.clone()).expect("add");
	store.add(key("other", "secret2")).expect("add");

	store.set_auto_submitted("apps", true).expect("set on");
	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	let changed = reopened
		.keys()
		.iter()
		.find(|key| key.label == "apps")
		.expect("kept");
	assert!(changed.auto_submitted);
	assert_eq!(changed.hash, full.hash);
	assert_eq!(changed.scopes, full.scopes);
	assert_eq!(changed.domains, full.domains);
	assert_eq!(changed.account, full.account);
	assert_eq!(changed.expires_at, full.expires_at);
	assert_eq!(changed.ip_cidr, full.ip_cidr);
	let other = reopened
		.keys()
		.iter()
		.find(|key| key.label == "other")
		.expect("kept");
	assert!(!other.auto_submitted, "another key's setting is untouched");

	store.set_auto_submitted("apps", false).expect("set off");
	let reopened = ApiKeyStore::open(dir.path()).expect("reopen");
	assert!(!reopened.keys()[0].auto_submitted);
}

/// A label that is not there is `NotFound` and the file is not rewritten.
#[test]
fn set_auto_submitted_rejects_an_unknown_label() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = ApiKeyStore::open(dir.path()).expect("open");
	store.add(key("apps", "secret1")).expect("add");
	let path = dir.path().join("api_keys.toml");
	let before = std::fs::read(&path).expect("read");
	let error = store
		.set_auto_submitted("missing", true)
		.expect_err("unknown label");
	assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
	assert_eq!(std::fs::read(&path).expect("read"), before);
	assert!(!store.keys()[0].auto_submitted);
}

/// A value that is not a boolean is refused by the loader and by the
/// watcher's reload, and the running set keeps what it had.
#[test]
fn invalid_auto_submitted_value_is_rejected() {
	let bad = format!(
		"[[keys]]\nlabel = \"bad\"\nhash = \"{ZERO_HASH}\"\nscopes = [\"send\"]\nauto_submitted = \"yes\"\n"
	);
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("api_keys.toml"), &bad).expect("write fixture");
	assert!(ApiKeyStore::open(dir.path()).is_err());
	assert!(ApiKeySet::open(dir.path()).is_err());

	let set = ApiKeySet::empty();
	set.reload_from(&format!(
		"[[keys]]\nlabel = \"good\"\nhash = \"{ZERO_HASH}\"\nscopes = [\"send\"]\nauto_submitted = true\n"
	))
	.expect("valid reload");
	assert!(set.reload_from(&bad).is_err());
	let snapshot = set.snapshot();
	assert_eq!(snapshot.len(), 1);
	assert_eq!(snapshot[0].label, "good");
	assert!(snapshot[0].auto_submitted, "the running set is unchanged");
}
