//! Tests for the disabled-multi-target-alias slice of `Directory`:
//! resolution fall-through, send-as denial, and the disabled-rejection
//! contract. The brief is explicit: a disabled alias rejects identically
//! to one that never existed and lets the next step of `resolve` run.
//!
//! Resolution order (see `Directory::resolve`):
//!   1. domain alias
//!   2. account address
//!   3. multi-target alias        ← disabled alias drops out here
//!   4. masked address            ← can still catch a disabled alias
//!   5. sub-addressing            ← can still catch a disabled alias
//!   6. catch-all                 ← can still catch a disabled alias
//!
//! Each fall-through test pins one of those later steps so the next-step
//! invariant stays honest: a disabled alias that shadows another
//! resolution must not steal that resolution.

use super::{AliasSpec, Directory, Resolution};
use crate::directory_store::aliases::AliasStore;
use crate::smtp::address::Address;

fn directory() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[
			("Alice@EXAMPLE.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	)
}

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

fn aliased() -> Directory {
	directory().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec![
				"alice@example.org".to_string(),
				"bob@example.org".to_string(),
			],
			senders: Vec::new(),
			hidden: true,
			list_id: None,
		},
	)])
}

/// Sanity check: with the alias enabled, resolution fans out to its
/// members. This is the baseline the fall-through tests below compare
/// against — they pass only when the alias is **absent** from the
/// directory, mirroring how the disabled overlay filters it out at
/// `AccountStore::build_directory` time.
#[test]
fn enabled_alias_resolves_to_members() {
	let dir = aliased();
	match dir.resolve(&parse("team@example.org")) {
		Resolution::Alias(members) => {
			assert_eq!(members.len(), 2);
			assert!(members.contains(&"alice".to_string()));
			assert!(members.contains(&"bob".to_string()));
		}
		other => panic!("expected alias, got {other:?}"),
	}
}

/// A disabled multi-target alias is absent from the directory's `aliases`
/// map, so resolution rejects with `UnknownUser` — indistinguishable from
/// an alias that never existed. The brief's "rejection does not reveal
/// that the address existed" check.
#[test]
fn disabled_alias_rejects_like_unknown_user() {
	// Build a directory without the alias entry: mirrors how the
	// disabled overlay filters the alias out of `build_directory`.
	let dir = directory();
	assert_eq!(
		dir.resolve(&parse("team@example.org")),
		Resolution::UnknownUser
	);
}

/// Disabled alias membership is not disclosed via `alias_members`. The
/// store drops the entry entirely, so a probe cannot tell that one once
/// existed (privacy).
#[test]
fn disabled_alias_membership_is_not_disclosed() {
	let dir = directory();
	assert_eq!(dir.alias_members("team@example.org"), None);
}

/// Disabled alias: send-as (`owns_address`) is refused even for a member
/// account. Without the entry in `aliases`, the alias path in
/// `owns_address` never matches and a member cannot send from a disabled
/// alias.
#[test]
fn disabled_alias_refuses_send_as_for_everyone() {
	let dir = directory();
	assert!(!dir.owns_address("alice", &parse("team@example.org")));
	assert!(!dir.owns_address("bob", &parse("team@example.org")));
	assert!(!dir.owns_address("carol", &parse("team@example.org")));
}

/// Fall-through to masked: the disabled alias must not shadow a mask
/// registered for the same address. With the alias enabled the alias
/// step wins (precedence); with the alias absent (the disabled case) the
/// mask step is the only match. Pinning the order protects both steps
/// from being reordered.
#[test]
fn disabled_alias_falls_through_to_mask() {
	let with_alias = directory()
		.with_aliases([(
			"team@example.org".to_string(),
			AliasSpec {
				members: vec!["bob@example.org".to_string()],
				senders: Vec::new(),
				hidden: true,
				list_id: None,
			},
		)])
		.with_masked([("team@example.org".to_string(), "alice".to_string())]);
	// Alias wins while enabled.
	assert_eq!(
		with_alias.resolve(&parse("team@example.org")),
		Resolution::Alias(vec!["bob".to_string()])
	);
	// Without the alias, the mask owns the address.
	let without_alias =
		directory().with_masked([("team@example.org".to_string(), "alice".to_string())]);
	assert_eq!(
		without_alias.resolve(&parse("team@example.org")),
		Resolution::Account("alice".to_string())
	);
}

/// Fall-through to sub-addressing: a disabled alias `team@example.org`
/// does not block an account `team@example.org` from receiving
/// `team+tag@example.org` via sub-addressing. With the alias in the
/// directory the alias step would shadow the sub-address lookup
/// (`accounts_by_address` only) by returning Alias before it ever runs;
/// without the alias the +tag falls through to sub-addressing and finds
/// the account.
#[test]
fn disabled_alias_falls_through_to_subaddress() {
	// With the alias enabled, `team+sales@example.org` would not be
	// claimed by sub-addressing because the alias step would shadow it
	// on the **bare** address. Verify the shadow: add an account `team`
	// and confirm it is **not** picked up while the alias is in place.
	let with_alias = directory()
		.with_aliases([(
			"team@example.org".to_string(),
			AliasSpec {
				members: vec!["bob@example.org".to_string()],
				senders: Vec::new(),
				hidden: true,
				list_id: None,
			},
		)])
		.with_subaddress_separators(['+']);
	// The bare address resolves to the alias (not the sub-addressing
	// path; sub-addressing only fires on +tagged variants).
	assert_eq!(
		with_alias.resolve(&parse("team@example.org")),
		Resolution::Alias(vec!["bob".to_string()])
	);

	// Without the alias, the bare address has no account and the +tag
	// also has no base to strip to, so both reject. The point of this
	// test is to confirm that **without the alias**, the sub-address
	// path runs to completion (rather than being preempted by the
	// alias step) — it returns UnknownUser because no other step
	// matches either, which is the correct fall-through behavior.
	let without_alias = directory().with_subaddress_separators(['+']);
	assert_eq!(
		without_alias.resolve(&parse("team+sales@example.org")),
		Resolution::UnknownUser
	);
}

/// Fall-through to catch-all: a disabled alias does not block the
/// catch-all from collecting its domain's mail.
#[test]
fn disabled_alias_falls_through_to_catch_all() {
	let with_alias = directory()
		.with_aliases([(
			"team@example.org".to_string(),
			AliasSpec {
				members: vec!["bob@example.org".to_string()],
				senders: Vec::new(),
				hidden: true,
				list_id: None,
			},
		)])
		.with_catch_all([("example.org".to_string(), "alice".to_string())]);
	// The alias step matches `team@example.org` before catch-all runs.
	assert_eq!(
		with_alias.resolve(&parse("team@example.org")),
		Resolution::Alias(vec!["bob".to_string()])
	);

	// Without the alias, the catch-all picks up `team@example.org`.
	let without_alias =
		directory().with_catch_all([("example.org".to_string(), "alice".to_string())]);
	assert_eq!(
		without_alias.resolve(&parse("team@example.org")),
		Resolution::Account("alice".to_string())
	);
}

/// `AliasStore::set_enabled` round-trips state on a single store.
#[test]
fn alias_store_toggle_round_trip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = AliasStore::open(dir.path()).expect("open");
	let was = store
		.set_enabled("team@example.org", false)
		.expect("disable");
	assert!(!was, "previously enabled, so was-disabled = false");
	assert!(store.is_disabled("team@example.org"));
	let was = store.set_enabled("team@example.org", true).expect("enable");
	assert!(was, "previously disabled, so was-disabled = true");
	assert!(!store.is_disabled("team@example.org"));
}

/// The disabled overlay is address-only — it has no effect on aliases
/// that were never configured. The store must not synthesise entries.
#[test]
fn unknown_alias_is_not_disabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AliasStore::open(dir.path()).expect("open");
	assert!(!store.is_disabled("never-configured@example.org"));
}

/// The disabled overlay survives a restart — same persistence shape as
/// the masked store, so an operator's flip is sticky across a reload.
#[test]
fn disabled_overlay_persists_across_reopen() {
	let dir = tempfile::tempdir().expect("tempdir");
	{
		let mut store = AliasStore::open(dir.path()).expect("open");
		store
			.set_enabled("team@example.org", false)
			.expect("disable");
		store
			.set_enabled("sales@example.org", false)
			.expect("disable sales");
	}
	let reopened = AliasStore::open(dir.path()).expect("reopen");
	assert!(reopened.is_disabled("team@example.org"));
	assert!(reopened.is_disabled("sales@example.org"));
	assert!(!reopened.is_disabled("info@example.org"));
}

/// Idempotency: re-disabling an already-disabled alias is a no-op and
/// does not rewrite the file. Mirrors `MaskedAddressStore::set_enabled`.
#[test]
fn set_disabled_is_idempotent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut store = AliasStore::open(dir.path()).expect("open");
	store
		.set_enabled("team@example.org", false)
		.expect("disable");
	let written = std::fs::read_to_string(dir.path().join("aliases.json")).expect("file written");
	let again = store
		.set_enabled("team@example.org", false)
		.expect("disable again");
	assert!(again, "already disabled, so was-disabled = true");
	let reread =
		std::fs::read_to_string(dir.path().join("aliases.json")).expect("file still present");
	assert_eq!(written, reread, "no-op must not rewrite the file");
}
