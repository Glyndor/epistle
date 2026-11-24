//! Who already holds an address, and which addresses belong to a local
//! account: the two questions the rules ask the directory, answered from the
//! same files `alias add` has always read.

use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::util::address::normalize;

/// The accounts and masked addresses of a data directory, as the rules read
/// them.
pub(super) struct Known {
	store: AccountStore,
	masked: Vec<String>,
}

impl Known {
	/// Open the account store of `config` and read the masked addresses.
	pub(super) fn open(config: &Config) -> Result<Self, String> {
		let store = AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			config.domain_aliases.clone(),
			config.accounts.clone(),
		)
		.map_err(|error| error.to_string())?;
		let masked = std::fs::read_to_string(config.data_dir.join("masked.json"))
			.ok()
			.and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
			.and_then(|file| {
				file.get("addresses")
					.and_then(|value| value.as_object())
					.map(|map| map.keys().map(|key| normalize(key)).collect())
			})
			.unwrap_or_default();
		Ok(Known { store, masked })
	}

	/// The reason `raw` cannot be the address of a new alias, when an account
	/// or a masked address already holds it. `raw` is normalized.
	pub(super) fn holder_of(&self, raw: &str) -> Option<String> {
		let held_by_account =
			self.store.account_views().iter().any(|(_, addresses, _)| {
				addresses.iter().any(|existing| normalize(existing) == raw)
			});
		if held_by_account {
			return Some(format!("alias address {raw} is already used by an account"));
		}
		if self.masked.iter().any(|existing| existing == raw) {
			return Some(format!(
				"alias address {raw} is already used by a masked address"
			));
		}
		None
	}

	/// Every address of the account that holds `raw` (normalized), or `None`
	/// when no account does.
	pub(super) fn addresses_of_account_holding(&self, raw: &str) -> Option<Vec<String>> {
		self.store
			.account_views()
			.into_iter()
			.find(|(_, addresses, _)| addresses.iter().any(|existing| normalize(existing) == raw))
			.map(|(_, addresses, _)| addresses)
	}
}
