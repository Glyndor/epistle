//! The stored form of a dynamic account's identifiers.
//!
//! Every address, forward target and catch-all domain in `accounts.toml` is
//! kept in the form [`crate::util::address`] returns. New values are
//! normalized by the mutators before they are checked or written; values
//! already on disk are normalized when the file is read, so the server and
//! the CLI see lowercase from the first read, and the next write (any
//! mutation rewrites the whole file) saves them that way.

use crate::util::address::{normalize, normalize_domain};

use super::{DynamicAccount, DynamicFile};

/// The account name in its stored form: trimmed, ASCII lowercase. The name
/// rule (`names::validate_name`) still decides whether it is acceptable.
pub fn account_name(raw: &str) -> String {
	raw.trim().to_ascii_lowercase()
}

/// Normalize every identifier of one account in place, dropping a value
/// that appears twice once normalized (it is the same mailbox, target or
/// domain on the same account, so nothing is lost).
pub(super) fn account(account: &mut DynamicAccount) {
	normalize_list(&mut account.addresses, normalize);
	normalize_list(&mut account.forward, normalize);
	normalize_list(&mut account.catch_all, normalize_domain);
}

/// Normalize every account of a parsed `accounts.toml`.
pub(super) fn file(mut file: DynamicFile) -> DynamicFile {
	file.accounts.iter_mut().for_each(account);
	file
}

fn normalize_list(values: &mut Vec<String>, normalize: fn(&str) -> String) {
	let mut seen = std::collections::HashSet::new();
	*values = values
		.iter()
		.map(|value| normalize(value))
		.filter(|value| seen.insert(value.clone()))
		.collect();
}

/// Re-key a parsed `masked.json` by the stored form of each address, with
/// the address and the owning account name in their stored forms too.
pub(super) fn masked(
	entries: std::collections::HashMap<String, super::MaskedAddress>,
) -> std::collections::HashMap<String, super::MaskedAddress> {
	entries
		.into_values()
		.map(|mut entry| {
			entry.address = normalize(&entry.address);
			entry.account = account_name(&entry.account);
			(entry.address.clone(), entry)
		})
		.collect()
}
