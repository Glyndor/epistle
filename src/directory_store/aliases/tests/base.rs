//! Tests for the alias disabled-overlay store.

use super::*;

fn store(dir: &std::path::Path) -> AliasStore {
	AliasStore::open(dir).expect("open")
}

#[test]
fn open_missing_file_yields_empty_overlay() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	assert!(!store.is_disabled("team@example.org"));
	assert_eq!(store.disabled_addresses().count(), 0);
}

#[test]
fn set_enabled_disables_then_re_enables() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	assert!(!store.is_disabled("team@example.org"));

	let was = store
		.set_enabled("team@example.org", false)
		.expect("disable");
	assert!(!was);
	assert!(store.is_disabled("team@example.org"));

	let was = store.set_enabled("team@example.org", true).expect("enable");
	assert!(was);
	assert!(!store.is_disabled("team@example.org"));
}

#[test]
fn lookup_is_case_insensitive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	store
		.set_enabled("Team@Example.org", false)
		.expect("disable");
	assert!(store.is_disabled("team@example.org"));
	assert!(store.is_disabled("TEAM@EXAMPLE.ORG"));
}

#[test]
fn set_enabled_is_idempotent_and_does_not_rewrite_unnecessarily() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	// Enabling an already-enabled alias is a no-op: no file is written.
	let before = std::fs::read_to_string(dir.path().join("aliases.json")).ok();
	store.set_enabled("team@example.org", true).expect("enable");
	let after = std::fs::read_to_string(dir.path().join("aliases.json")).ok();
	assert_eq!(before, after);

	// Disabling twice in a row also stays idempotent — same flag, no write.
	store
		.set_enabled("team@example.org", false)
		.expect("disable");
	let written = std::fs::read_to_string(dir.path().join("aliases.json")).expect("file");
	store
		.set_enabled("team@example.org", false)
		.expect("disable again");
	let again = std::fs::read_to_string(dir.path().join("aliases.json")).expect("file");
	assert_eq!(written, again);
}

#[test]
fn state_persists_across_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	{
		let mut store = store(dir.path());
		store
			.set_enabled("team@example.org", false)
			.expect("disable");
		store
			.set_enabled("sales@example.org", false)
			.expect("disable");
	}
	let reopened = store(dir.path());
	assert!(reopened.is_disabled("team@example.org"));
	assert!(reopened.is_disabled("sales@example.org"));
	assert!(!reopened.is_disabled("info@example.org"));
	assert_eq!(reopened.disabled_addresses().count(), 2);
}

#[test]
fn disabled_file_is_sorted_for_stable_diffs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	store.set_enabled("zeta@example.org", false).expect("z");
	store.set_enabled("alpha@example.org", false).expect("a");
	store.set_enabled("mu@example.org", false).expect("m");
	let text = std::fs::read_to_string(dir.path().join("aliases.json")).expect("file");
	let positions: Vec<_> = ["alpha", "mu", "zeta"]
		.into_iter()
		.map(|needle| text.find(needle).expect("present"))
		.collect();
	assert!(
		positions.windows(2).all(|w| w[0] < w[1]),
		"addresses are not sorted: {positions:?}"
	);
}

#[test]
fn unknown_alias_is_not_disabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	assert!(!store.is_disabled("never-touched@example.org"));
}
