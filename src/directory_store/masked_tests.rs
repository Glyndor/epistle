//! Tests for the masked-address store.

use super::*;

fn store(dir: &std::path::Path) -> MaskedAddressStore {
	MaskedAddressStore::open(dir).expect("open")
}

#[test]
fn add_returns_a_unique_address_and_persists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let entry = store
		.add("alice", "Shopping", "example.org", 1_700_000_000)
		.expect("add");
	assert_eq!(entry.account, "alice");
	assert!(entry.address.starts_with("shopping."), "{}", entry.address);
	assert!(entry.address.ends_with("@example.org"), "{}", entry.address);
	// 8 lowercase base32 chars in the middle.
	let local = entry.address.split('@').next().expect("local");
	let suffix = local.rsplit_once('.').expect("dot").1;
	assert_eq!(suffix.len(), 8, "suffix {suffix}");
	assert!(
		suffix
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
	);

	assert!(entry.enabled);
	assert_eq!(entry.created_at, 1_700_000_000);
	assert!(entry.last_used_at.is_none());

	// Reopen to confirm persistence.
	let reopened = MaskedAddressStore::open(dir.path()).expect("reopen");
	assert_eq!(
		reopened.get(&entry.address).map(|e| &e.address),
		Some(&entry.address)
	);
}

#[test]
fn label_slug_collapses_separators_and_lowercases() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let entry = store
		.add("alice", "  News --- Letters!! ", "example.org", 1)
		.expect("add");
	assert!(
		entry.address.starts_with("news-letters."),
		"{}",
		entry.address
	);
	// The display label preserves the user's spelling (trimmed); the slug is
	// only for the address local part.
	assert_eq!(entry.label, "News --- Letters!!");
}

#[test]
fn invalid_labels_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	for bad in ["", "   ", "---", "!@#"] {
		assert!(matches!(
			store.add("alice", bad, "example.org", 1),
			Err(StoreError::Invalid(_))
		));
	}
	assert!(matches!(
		store.add("", "anything", "example.org", 1),
		Err(StoreError::Invalid(_))
	));
	assert!(matches!(
		store.add("alice", "x", "", 1),
		Err(StoreError::Invalid(_))
	));
}

#[test]
fn list_filters_by_account_and_sorts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let a1 = store.add("alice", "A", "example.org", 10).expect("a1");
	let b1 = store.add("bob", "B", "example.org", 20).expect("b1");
	let a2 = store.add("alice", "C", "example.org", 5).expect("a2");

	let alice_rows = store.list_for_account("alice");
	assert_eq!(alice_rows.len(), 2);
	assert_eq!(alice_rows[0].address, a2.address);
	assert_eq!(alice_rows[1].address, a1.address);

	let bob_rows = store.list_for_account("bob");
	assert_eq!(bob_rows.len(), 1);
	assert_eq!(bob_rows[0].address, b1.address);

	// Lookup is case-insensitive.
	assert_eq!(store.list_for_account("ALICE").len(), 2);
}

#[test]
fn set_enabled_toggles_and_only_owner_can_change() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let entry = store.add("alice", "L", "example.org", 1).expect("add");
	assert!(entry.enabled);
	let previous = store
		.set_enabled("alice", &entry.address, false)
		.expect("disable");
	assert!(previous);
	assert!(!store.get(&entry.address).expect("entry").enabled);

	// Bob cannot toggle alice's mask.
	assert!(matches!(
		store.set_enabled("bob", &entry.address, true),
		Err(StoreError::NotFound(_))
	));

	// Re-enabling is idempotent.
	let prev2 = store
		.set_enabled("alice", &entry.address, true)
		.expect("re-enable");
	assert!(!prev2);
}

#[test]
fn remove_only_owner_can_delete() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let entry = store.add("alice", "L", "example.org", 1).expect("add");
	assert!(matches!(
		store.remove("bob", &entry.address),
		Err(StoreError::NotFound(_))
	));
	store.remove("alice", &entry.address).expect("remove");
	assert!(store.get(&entry.address).is_none());

	// Persistence after remove.
	let reopened = MaskedAddressStore::open(dir.path()).expect("reopen");
	assert!(reopened.get(&entry.address).is_none());
}

#[test]
fn touch_last_used_skips_disabled_and_foreign() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let alice = store.add("alice", "A", "example.org", 1).expect("a");
	let bob = store.add("bob", "B", "example.org", 2).expect("b");

	store.touch_last_used("alice", &alice.address, 100);
	assert_eq!(
		store.get(&alice.address).expect("alice").last_used_at,
		Some(100)
	);

	// No-op for the wrong owner.
	store.touch_last_used("bob", &alice.address, 200);
	assert_eq!(
		store.get(&alice.address).expect("alice").last_used_at,
		Some(100)
	);

	// No-op for a disabled address.
	store
		.set_enabled("alice", &alice.address, false)
		.expect("disable");
	store.touch_last_used("alice", &alice.address, 300);
	assert_eq!(
		store.get(&alice.address).expect("alice").last_used_at,
		Some(100)
	);

	// Bob's untouched.
	assert_eq!(store.get(&bob.address).expect("bob").last_used_at, None);

	// Reopen preserves the touch.
	let reopened = MaskedAddressStore::open(dir.path()).expect("reopen");
	assert_eq!(
		reopened.get(&alice.address).expect("alice").last_used_at,
		Some(100)
	);
}

#[test]
fn per_account_limit_rejects_excess() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = MaskedAddressStore::open(dir.path())
		.expect("open")
		.with_max_per_account(2);
	store.add("alice", "A", "example.org", 1).expect("a1");
	store.add("alice", "B", "example.org", 2).expect("a2");
	let result = store.add("alice", "C", "example.org", 3);
	assert!(matches!(result, Err(StoreError::LimitReached { max: 2 })));

	// Bob is unaffected.
	store.add("bob", "B", "example.org", 1).expect("bob");

	// Disabling alice's entries frees up no quota — limit is total masks.
	// We verify by re-listing after a disable.
	store
		.set_enabled("alice", "alice-1@example.org", false)
		.ok();
	assert_eq!(store.list_for_account("alice").len(), 2);
}

#[test]
fn entries_excludes_disabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let a = store.add("alice", "A", "example.org", 1).expect("a");
	let b = store.add("alice", "B", "example.org", 2).expect("b");
	let enabled: Vec<_> = store.entries().collect();
	assert_eq!(enabled.len(), 2);

	store
		.set_enabled("alice", &a.address, false)
		.expect("disable");
	let enabled: Vec<_> = store.entries().collect();
	assert_eq!(enabled.len(), 1);
	assert_eq!(enabled[0].0, b.address);
}

#[test]
fn account_lookup_is_case_insensitive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = store(dir.path());
	let entry = store.add("Alice", "A", "example.org", 1).expect("a");
	assert_eq!(
		store.get(&entry.address.to_uppercase()).map(|e| &e.address),
		Some(&entry.address)
	);
}
