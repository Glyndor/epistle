//! Tests for `crate::storage::correspondents`.

use std::time::Duration;

use super::*;

/// Open a correspondent store rooted at the tempdir.
fn open(dir: &std::path::Path) -> CorrespondentStore {
	CorrespondentStore::open(dir).expect("open")
}

/// Record twice; the second call reports the address as known, not new.
#[test]
fn recording_creates_a_marker_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path());
	let first = store
		.record("alice@example.org", &["bob@example.net"])
		.expect("first");
	assert_eq!(first.new, 1);
	assert_eq!(first.known, 0);
	let second = store
		.record("alice@example.org", &["bob@example.net"])
		.expect("second");
	assert_eq!(second.new, 0);
	assert_eq!(second.known, 1);
	// And the marker is what `knows` reports.
	assert!(store.knows("alice@example.org", "bob@example.net"));
}

/// Markers older than 24 h do not count toward the daily limit.
#[test]
fn new_in_last_day_counts_only_recent_markers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path());
	store
		.record("alice@example.org", &["fresh@example.net"])
		.expect("record fresh");
	// Backdate the marker two days so it sits outside the 24h window.
	// `File::set_modified` is stable since Rust 1.75 and is the
	// `filetime`-free path the brief asks for.
	let marker = store.marker("alice@example.org", "fresh@example.net");
	let stale = std::time::SystemTime::now() - Duration::from_secs(2 * 86400);
	std::fs::File::options()
		.write(true)
		.open(&marker)
		.expect("open")
		.set_modified(stale)
		.expect("backdate");
	assert_eq!(
		store.new_in_last_day("alice@example.org").expect("count"),
		0,
		"the backdated marker must not count"
	);
	// A second marker with current mtime is the one that counts.
	store
		.record("alice@example.org", &["today@example.net"])
		.expect("record today");
	assert_eq!(
		store.new_in_last_day("alice@example.org").expect("count"),
		1
	);
}

/// `knows` matches the address case-insensitively.
#[test]
fn knows_is_case_insensitive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path());
	store
		.record("alice@example.org", &["Bob@Example.NET"])
		.expect("record");
	assert!(store.knows("alice@example.org", "bob@example.net"));
	assert!(store.knows("alice@example.org", "BOB@EXAMPLE.NET"));
	assert!(!store.knows("alice@example.org", "carol@example.net"));
	// And the account itself is matched case-insensitively: the digest
	// hashes the lowercased account name, so a different-case account
	// resolves to the same marker.
	assert!(store.knows("ALICE@example.org", "bob@example.net"));
}

/// `remove_all_for` drops only the requested account's markers; a missing
/// account returns zero; another account's set is untouched.
#[test]
fn remove_all_for_leaves_other_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open(dir.path());
	store
		.record("alice@example.org", &["a@example.net", "b@example.net"])
		.expect("alice");
	store
		.record("carol@example.org", &["c@example.net"])
		.expect("carol");

	let removed = store.remove_all_for("alice@example.org").expect("remove");
	assert_eq!(removed, 2);
	assert!(!store.knows("alice@example.org", "a@example.net"));
	assert!(!store.knows("alice@example.org", "b@example.net"));
	assert!(store.knows("carol@example.org", "c@example.net"));
	// Idempotent: the second call returns zero, not an error.
	assert_eq!(store.remove_all_for("alice@example.org").expect("again"), 0);
	// Missing account is `Ok(0)`, not an error.
	assert_eq!(store.remove_all_for("ghost@example.org").expect("ghost"), 0);
	// The empty parent dir is gone, so a recreated account starts clean.
	assert!(!store.account_dir("alice@example.org").exists());
}
