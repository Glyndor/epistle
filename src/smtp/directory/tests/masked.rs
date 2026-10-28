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
/// `UnknownUser` exactly like an address that never existed. The contract is
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
/// one takes precedence (masks resolve after static aliases).
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

/// A mask must win over sub-addressing of a real account. The masked
/// address carries the bare local part `alice` (which would be a sub-
/// addressing collision if `alice+news` were instead the mask: the
/// `MaskedAddressStore` would slugify the `+` away, so the directory
/// sees `<label-slug>.<8 chars>@domain`; a synthetic collision is built
/// here by giving `alice@example.org` an explicit account and putting a
/// mask on `alice+news@example.org`).
///
/// Without this ordering, sub-addressing would strip `alice+news` to
/// `alice@example.org` and deliver to `alice`, bypassing the mask owner's
/// intent.
#[test]
fn a_mask_beats_subaddressing_of_a_real_account() {
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_subaddress_separators(['+'])
	.with_masked([("alice+news@example.org".to_string(), "bob".to_string())]);
	assert_eq!(
		directory.resolve(&parse("alice+news@example.org")),
		Resolution::Account("bob".to_string()),
		"the mask owns alice+news, not the sub-addressed alice"
	);
}

/// A mask must win over the per-domain catch-all. A catch-all that funnels
/// `example.org`'s unknown local users to `carol` is overridden for any
/// local part that also has a mask: the mask's owner (`bob`) takes the
/// message. Without this ordering, an operator who registers a mask would
/// silently lose the delivery to the catch-all account, contradicting the
/// "masks are per-owner addresses" contract.
#[test]
fn a_mask_beats_the_catch_all() {
	let directory = Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
		],
	)
	.with_catch_all([("example.org".to_string(), "carol".to_string())])
	.with_masked([("hidden@example.org".to_string(), "bob".to_string())]);
	assert_eq!(
		directory.resolve(&parse("hidden@example.org")),
		Resolution::Account("bob".to_string()),
		"the mask beats the catch-all"
	);
	// Sanity: the catch-all still fires for an address no other step
	// claims.
	assert_eq!(
		directory.resolve(&parse("stranger@example.org")),
		Resolution::Account("carol".to_string()),
		"the catch-all still fires when no other step claims the address"
	);
}

/// The config validator refuses `domain_aliases = {a.example: b.example}`
/// when both `a.example` and `b.example` are in `domains` (see
/// `validate_domains` in `src/config/validate.rs`). This pins the refusal:
/// a future refactor that loosens the validator must decide whether the
/// alias key is rewritten, whether the target domain is rewritten, or
/// whether the entry is silently dropped, and the test must then pin
/// which. As it stands, the rejection is the contract: the same name
/// cannot be both a domain and an alias, so the question of "which one
/// wins" never arises.
#[test]
fn a_real_domain_is_not_rewritten_by_a_domain_alias_of_the_same_name() {
	let toml = "hostname = \"mail.example.org\"\n\
data_dir = \"/var/lib/mail\"\n\
domains = [\"a.example\", \"b.example\"]\n\
[domain_aliases]\n\
\"a.example\" = \"b.example\"\n";
	let parsed: crate::config::Config = toml::from_str(toml).expect("parses");
	let error = parsed.validate().expect_err("validator refuses the alias");
	let message = error.to_string();
	assert!(
		message.contains("a.example") && message.contains("b.example"),
		"refusal must name both domains: {message}"
	);
}
