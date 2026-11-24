//! `epistle alias`: looking up aliases and reading the disabled overlay.

use std::collections::HashSet;

use crate::config::{Alias, Config};
use crate::util::address::normalize;

/// Find one alias by address, whatever its spelling.
pub(super) fn find_alias<'a>(config: &'a Config, address: &str) -> Option<&'a Alias> {
	let wanted = normalize(address);
	config
		.alias
		.iter()
		.find(|alias| normalize(&alias.address) == wanted)
}

/// Read the disabled-overlay file directly when possible, falling back to
/// an empty set on any I/O or parse error so `list`/`show` never block on
/// a malformed JSON file.
pub(in crate::cli) fn disabled_set(config: &Config) -> Option<HashSet<String>> {
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
