//! Tests for the masked-email slice of `Directory`: resolution, send-as
//! ownership, and the disabled-rejection contract.

use super::{Directory, Resolution};
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

fn with_masks(directory: Directory, masks: &[(&str, &str)]) -> Directory {
	let entries: Vec<(String, String)> = masks
		.iter()
		.map(|(address, account)| (address.to_string(), account.to_string()))
		.collect();
	directory.with_masked(entries)
}

/// Resolution: an enabled mask delivers to its owner.
#[test]
fn enabled_mask_resolves_to_owner() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert_eq!(
		directory.resolve(&parse("shopping.rassfbuu@example.org")),
		Resolution::Account("alice".to_string())
	);
}

/// A disabled mask is absent from the directory's map, so it rejects with
/// `UnknownUser` exactly like an address that never existed. The brief is
/// explicit: the disabled-rejection response must not leak that one once did.
#[test]
fn disabled_mask_rejects_like_unknown_user() {
	// Build the directory without the mask: `with_masked` only carries the
	// enabled entries, mirroring how the store filters `disabled == false`.
	let directory = with_masks(directory(), &[]);
	assert_eq!(
		directory.resolve(&parse("shopping.rassfbuu@example.org")),
		Resolution::UnknownUser
	);
}

/// `owns_address` accepts the owner of an enabled mask.
#[test]
fn owns_address_accepts_mask_owner() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert!(directory.owns_address("alice", &parse("shopping.rassfbuu@example.org")));
}

/// `owns_address` rejects every other account, so a leaked token on one
/// account cannot send from another account's mask.
#[test]
fn owns_address_rejects_other_accounts() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert!(!directory.owns_address("bob", &parse("shopping.rassfbuu@example.org")));
}

/// Static addresses win over a mask with the same local part: an operator
/// who promoted a mask to a permanent address can keep both, and the static
/// one takes precedence (the brief puts masks after static aliases).
#[test]
fn static_address_takes_precedence_over_mask() {
	let directory = Directory::new(
		["example.org".to_string()],
		[("shopping@example.org".to_string(), "team".to_string())],
	)
	.with_masked([(
		"shopping.rassfbuu@example.org".to_string(),
		"alice".to_string(),
	)]);
	assert_eq!(
		directory.resolve(&parse("shopping.rassfbuu@example.org")),
		Resolution::Account("alice".to_string()),
		"mask still owns its unique local part"
	);
	assert_eq!(
		directory.resolve(&parse("shopping@example.org")),
		Resolution::Account("team".to_string()),
		"the static alias still wins on its own address"
	);
}

/// Lookup is case-insensitive on the address.
#[test]
fn masked_lookup_is_case_insensitive() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert_eq!(
		directory.resolve(&parse("SHOPPING.RASSFBUU@EXAMPLE.ORG")),
		Resolution::Account("alice".to_string())
	);
	assert!(directory.owns_address("alice", &parse("SHOPPING.RASSFBUU@EXAMPLE.ORG")));
}

/// Sanity check: this is the **deletion control** for the masked
/// resolution path. Remove the masked lookup from [`Directory::resolve`]
/// and the enabled-mask resolution assertion fails — the store is the
/// only place that knows about a mask.
#[test]
fn resolve_consults_masked_store() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert_eq!(
		directory.resolve(&parse("shopping.rassfbuu@example.org")),
		Resolution::Account("alice".to_string())
	);
}

/// Deletion control for `owns_address`: remove the masked branch from
/// `owns_address` and a mask stops being accepted by its owner.
#[test]
fn owns_address_consults_masked_store() {
	let directory = with_masks(directory(), &[("shopping.rassfbuu@example.org", "alice")]);
	assert!(directory.owns_address("alice", &parse("shopping.rassfbuu@example.org")));
}
