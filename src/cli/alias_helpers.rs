//! `epistle alias`: helpers for validating an alias address against the
//! directory store, looking up aliases and reading the disabled overlay.

use std::collections::HashSet;

use crate::cli::config_edit::ConfigDocument;
use crate::config::{Alias, Config};
use crate::directory_store::AccountStore;
use crate::util::address::normalize;
use crate::util::address_reason;

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
	let parsed = address_reason::parse(raw).map_err(|why| format!("alias address: {why}"))?;
	if !config
		.domains
		.iter()
		.any(|domain| domain.eq_ignore_ascii_case(parsed.domain()))
	{
		return Err(format!(
			"alias address: {}",
			address_reason::not_handled(parsed.domain())
		));
	}
	let raw = &normalize(raw);
	let used_by_account = config
		.accounts
		.iter()
		.flat_map(|account| account.addresses.iter())
		.any(|existing| normalize(existing) == *raw);
	if used_by_account {
		return Err(format!("alias address {raw} is already used by an account"));
	}
	for dynamic in store.dynamic_accounts() {
		if dynamic
			.addresses
			.iter()
			.any(|existing| normalize(existing) == *raw)
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
			if normalize(key) == *raw {
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
	let parsed = address_reason::parse(raw).map_err(|why| format!("{label} address: {why}"))?;
	if parsed.local_part().is_empty() || parsed.domain().is_empty() {
		return Err(format!("{label} address {raw} is empty"));
	}
	Ok(())
}

/// Find one alias by address, whatever its spelling.
pub(super) fn find_alias<'a>(config: &'a Config, address: &str) -> Option<&'a Alias> {
	let wanted = normalize(address);
	config
		.alias
		.iter()
		.find(|alias| normalize(&alias.address) == wanted)
}

/// The `[[alias]]` address as the file spells it, for edits that match the
/// element by its key; the stored form when the file has no such alias yet.
pub(super) fn document_address(document: &ConfigDocument, address: &str) -> String {
	let wanted = normalize(address);
	document
		.element_value("alias", "address", |raw| normalize(raw) == wanted)
		.unwrap_or(wanted)
}

/// Every address in its stored form.
pub(super) fn normalized(addresses: &[String]) -> Vec<String> {
	addresses.iter().map(|address| normalize(address)).collect()
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
