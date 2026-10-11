//! `epistle alias`: helpers for validating an alias address against the
//! directory store, looking up aliases and reading the disabled overlay.

use std::collections::HashSet;

use crate::config::{Alias, Config};
use crate::directory_store::AccountStore;
use crate::smtp::address::Address;

/// Validate that `raw` is a syntactically valid email address whose
/// domain is configured, and that no other owner already uses it.
/// Mirrors the `address_taken` rule `AccountStore::add` enforces for
/// dynamic accounts, applied to the public surfaces the CLI can read:
/// static accounts, dynamic accounts, masked addresses and existing
/// aliases (the duplicate-alias case is caught earlier in `add_alias`).
pub(super) fn validate_alias_address(
	config: &Config,
	raw: &str,
	store: &AccountStore,
) -> Result<(), String> {
	let parsed = Address::parse(raw)
		.map_err(|_| format!("alias address {raw} is not a valid email address"))?;
	if !config
		.domains
		.iter()
		.any(|domain| domain.eq_ignore_ascii_case(parsed.domain()))
	{
		return Err(format!("alias address {raw} is not in a configured domain"));
	}
	let used_by_account = config
		.accounts
		.iter()
		.flat_map(|account| account.addresses.iter())
		.any(|existing| existing.eq_ignore_ascii_case(raw));
	if used_by_account {
		return Err(format!("alias address {raw} is already used by an account"));
	}
	for dynamic in store.dynamic_accounts() {
		if dynamic
			.addresses
			.iter()
			.any(|existing| existing.eq_ignore_ascii_case(raw))
		{
			return Err(format!("alias address {raw} is already used by an account"));
		}
	}
	let masked_path = config.data_dir.join("masked.json");
	if let Ok(text) = std::fs::read_to_string(&masked_path)
		&& let Ok(file) = serde_json::from_str::<serde_json::Value>(&text)
		&& let Some(addresses) = file.get("addresses").and_then(|v| v.as_object())
	{
		for key in addresses.keys() {
			if key.eq_ignore_ascii_case(raw) {
				return Err(format!(
					"alias address {raw} is already used by a masked address"
				));
			}
		}
	}
	Ok(())
}

/// Parse every member/sender address: same rules as `validate_alias_address`
/// but does not check against the store (the alias itself is allowed to
/// deliver to addresses the directory cannot route to).
pub(super) fn validate_member_or_sender(label: &str, raw: &str) -> Result<(), String> {
	let parsed = Address::parse(raw)
		.map_err(|_| format!("{label} address {raw} is not a valid email address"))?;
	if parsed.local_part().is_empty() || parsed.domain().is_empty() {
		return Err(format!("{label} address {raw} is empty"));
	}
	Ok(())
}

/// Find one alias by address, case-insensitively.
pub(super) fn find_alias<'a>(config: &'a Config, address: &str) -> Option<&'a Alias> {
	config
		.alias
		.iter()
		.find(|alias| alias.address.eq_ignore_ascii_case(address))
}

/// Read the disabled-overlay file directly when possible, falling back to
/// an empty set on any I/O or parse error so `list`/`show` never block on
/// a malformed JSON file.
pub(super) fn disabled_set(config: &Config) -> Option<HashSet<String>> {
	let path = config.data_dir.join("aliases.json");
	let text = std::fs::read_to_string(&path).ok()?;
	let file: serde_json::Value = serde_json::from_str(&text).ok()?;
	let addresses = file.get("addresses").and_then(|v| v.as_array())?;
	Some(
		addresses
			.iter()
			.filter_map(|value| value.as_str())
			.map(|address| address.to_ascii_lowercase())
			.collect(),
	)
}
