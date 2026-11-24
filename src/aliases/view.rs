//! The aliases as `epistle alias list --json` and `epistle alias show --json`
//! print them and the `/api/v1/aliases` routes answer with them, so a route
//! and the command show one alias in one shape.

use std::collections::HashSet;

use serde::Serialize;

use crate::config::{Alias, Config};
use crate::util::address::normalize;

/// One alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AliasRow {
	/// The alias address.
	pub address: String,
	/// The member addresses it delivers to.
	pub members: Vec<String>,
	/// The addresses allowed to send as it; empty means any member.
	pub senders: Vec<String>,
	/// Whether the membership stays out of directory queries.
	pub hidden: bool,
	/// The mailing-list identifier, when it is a list.
	pub list_id: Option<String>,
	/// `false` when `epistle alias disable` switched it off.
	pub enabled: bool,
}

impl AliasRow {
	/// The row of `alias`, with its enabled flag from `disabled`.
	pub fn of(alias: &Alias, disabled: &HashSet<String>) -> Self {
		AliasRow {
			address: alias.address.clone(),
			members: alias.members.clone(),
			senders: alias.senders.clone(),
			hidden: alias.hidden,
			list_id: alias.list_id.clone(),
			enabled: !disabled.contains(&alias.address.to_ascii_lowercase()),
		}
	}
}

/// The addresses `epistle alias disable` switched off, lowercased. A file
/// that is missing or does not parse is an empty set, so a listing never
/// stops on it.
pub fn disabled_set(config: &Config) -> HashSet<String> {
	let path = config.data_dir.join("aliases.json");
	let Ok(text) = std::fs::read_to_string(path) else {
		return HashSet::new();
	};
	let Ok(file) = serde_json::from_str::<serde_json::Value>(&text) else {
		return HashSet::new();
	};
	file.get("addresses")
		.and_then(|value| value.as_array())
		.map(|addresses| {
			addresses
				.iter()
				.filter_map(|value| value.as_str())
				.map(|address| address.to_ascii_lowercase())
				.collect()
		})
		.unwrap_or_default()
}

/// Every alias of `config`, in the order of the state.
pub fn rows(config: &Config) -> Vec<AliasRow> {
	let disabled = disabled_set(config);
	config
		.alias
		.iter()
		.map(|alias| AliasRow::of(alias, &disabled))
		.collect()
}

/// The alias at `address`, whatever its spelling.
pub fn row(config: &Config, address: &str) -> Option<AliasRow> {
	let wanted = normalize(address);
	rows(config)
		.into_iter()
		.find(|row| normalize(&row.address) == wanted)
}
