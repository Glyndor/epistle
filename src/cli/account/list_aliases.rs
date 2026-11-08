//! `account list --aliases`: which address aliases (`[[alias]]`) deliver to
//! which account.
//!
//! An alias hangs under every account that owns at least one of its member
//! addresses, so an alias with members in two accounts shows under both.
//! A disabled alias is kept and marked, never hidden. Members that are not
//! an address of a local account have no account to show them under, so an
//! alias with no such member at all is counted instead of dropped, and the
//! caller says how to see them. Domain aliases are a different mapping and
//! are not read here.

use std::collections::{BTreeSet, HashMap};

use serde_json::{Value, json};

use crate::cli::alias::disabled_set;
use crate::config::Config;
use crate::util::address::normalize;

/// One address alias as it appears under an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasRef {
	pub(crate) address: String,
	pub(crate) enabled: bool,
	pub(crate) hidden: bool,
}

impl AliasRef {
	/// The keys `alias show --json` uses for the same three facts.
	pub(crate) fn to_json(&self) -> Value {
		json!({
			"address": self.address,
			"enabled": self.enabled,
			"hidden": self.hidden,
		})
	}

	/// The line printed under the account.
	pub(crate) fn line(&self) -> String {
		if self.enabled {
			format!("  alias {}", self.address)
		} else {
			format!("  alias {} (disabled)", self.address)
		}
	}
}

/// The aliases of every account, plus how many deliver to no local account.
#[derive(Debug, Default)]
pub(crate) struct Attached {
	by_account: HashMap<String, Vec<AliasRef>>,
	pub(crate) unattached: usize,
}

impl Attached {
	/// The aliases under `account`, sorted by address.
	pub(crate) fn of(&self, account: &str) -> &[AliasRef] {
		self.by_account.get(account).map_or(&[], Vec::as_slice)
	}

	/// The closing line when some alias hangs from no account, `None`
	/// when every alias was shown.
	pub(crate) fn summary(&self) -> Option<String> {
		let text = match self.unattached {
			0 => return None,
			1 => "1 alias delivers to no local account".to_string(),
			n => format!("{n} aliases deliver to no local account"),
		};
		Some(format!("{text}; see them with `epistle alias list`"))
	}
}

/// Match every configured alias against the accounts in `views` (name,
/// addresses, dynamic) by member address.
pub(crate) fn attach(config: &Config, views: &[(String, Vec<String>, bool)]) -> Attached {
	let disabled = disabled_set(config).unwrap_or_default();
	let mut owners: HashMap<String, Vec<&str>> = HashMap::new();
	for (name, addresses, _) in views {
		for address in addresses {
			owners.entry(normalize(address)).or_default().push(name);
		}
	}
	let mut aliases: Vec<_> = config.alias.iter().collect();
	aliases.sort_by_key(|entry| normalize(&entry.address));
	let mut attached = Attached::default();
	for entry in aliases {
		let accounts: BTreeSet<&str> = entry
			.members
			.iter()
			.filter_map(|member| owners.get(&normalize(member)))
			.flatten()
			.copied()
			.collect();
		if accounts.is_empty() {
			attached.unattached += 1;
			continue;
		}
		let row = AliasRef {
			address: entry.address.clone(),
			enabled: !disabled.contains(&entry.address.to_ascii_lowercase()),
			hidden: entry.hidden,
		};
		for account in accounts {
			attached
				.by_account
				.entry(account.to_string())
				.or_default()
				.push(row.clone());
		}
	}
	attached
}
