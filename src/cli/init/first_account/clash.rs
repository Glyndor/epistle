//! The collision check of the first account: whether its name or address is already held, in the data directory, the config or an alias.

use std::path::Path;

use super::FirstAccount;
use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::util::address::normalize;

/// Whether the account named `name` already exists and is the one `address`
/// asks for (`Ok(true)`), does not exist (`Ok(false)`), or exists under other
/// addresses (an error: the collision).
pub(super) fn name_is_free_or_ours(
	name: &str,
	address: &str,
	store: &AccountStore,
	static_accounts: &[(String, Vec<String>)],
) -> Result<bool, String> {
	let holder: Option<Vec<String>> = store
		.dynamic(name)
		.map(|existing| existing.addresses)
		.or_else(|| {
			static_accounts
				.iter()
				.find(|(static_name, _)| static_name == name)
				.map(|(_, addresses)| addresses.clone())
		});
	match holder {
		Some(holder) => name_holder(name, address, &holder),
		None => Ok(false),
	}
}

/// Whether the address is free for the account `owner`: no alias, masked
/// address or other account holds it, compared in the form the system stores.
/// The account `owner` itself may already hold it, which is a re-run; with
/// no owner the address must be free of every account.
pub(super) fn address_is_free_or_ours(
	owner: Option<&str>,
	address: &str,
	store: &AccountStore,
	static_accounts: &[(String, Vec<String>)],
	aliases: &[String],
) -> Result<(), String> {
	let wanted = normalize(address);
	if aliases.iter().any(|existing| normalize(existing) == wanted) {
		return Err(format!(
			"the address {address} is already used by an alias; use another address"
		));
	}
	if store
		.masked_handle()
		.read()
		.expect("masked lock")
		.get(address)
		.is_some()
	{
		return Err(format!(
			"the address {address} is already used by a masked address; use another address"
		));
	}
	let dynamic_owner = store
		.dynamic_accounts()
		.into_iter()
		.find(|account| {
			Some(account.name.as_str()) != owner
				&& account
					.addresses
					.iter()
					.any(|existing| normalize(existing) == wanted)
		})
		.map(|account| account.name);
	let static_owner = static_accounts.iter().find_map(|(holder, addresses)| {
		if Some(holder.as_str()) != owner
			&& addresses
				.iter()
				.any(|existing| normalize(existing) == wanted)
		{
			Some(holder.clone())
		} else {
			None
		}
	});
	if let Some(holder) = dynamic_owner.or(static_owner) {
		return Err(format!(
			"the address {address} is already used by the account \"{holder}\"; use another address"
		));
	}
	Ok(())
}

/// The `[[accounts]]` of a configuration file as name and addresses, read
/// from the raw TOML so a file the full loader refuses still counts.
pub(super) fn static_accounts_of(config_path: &Path) -> Vec<(String, Vec<String>)> {
	let Ok(text) = crate::cli::regular::read::read_to_string(config_path) else {
		return Vec::new();
	};
	let Ok(table) = text.parse::<toml::Table>() else {
		return Vec::new();
	};
	let Some(accounts) = table.get("accounts").and_then(|v| v.as_array()) else {
		return Vec::new();
	};
	accounts
		.iter()
		.filter_map(|entry| {
			let name = entry.get("name")?.as_str()?.to_string();
			let addresses = entry
				.get("addresses")
				.and_then(|v| v.as_array())
				.map(|list| {
					list.iter()
						.filter_map(|a| a.as_str().map(str::to_string))
						.collect()
				})
				.unwrap_or_default();
			Some((name, addresses))
		})
		.collect()
}

/// The addresses of the `[[alias]]` entries of a configuration file, read from
/// the raw TOML so a file the full loader refuses still counts.
pub(super) fn static_aliases_of(config_path: &Path) -> Vec<String> {
	let Ok(text) = crate::cli::regular::read::read_to_string(config_path) else {
		return Vec::new();
	};
	let Ok(table) = text.parse::<toml::Table>() else {
		return Vec::new();
	};
	table
		.get("alias")
		.and_then(|value| value.as_array())
		.into_iter()
		.flatten()
		.filter_map(|entry| entry.get("address")?.as_str().map(str::to_string))
		.collect()
}

/// The collision check that needs no write: with a configuration already on
/// disk, whether an account other than the one asked for holds the derived
/// name, or whether another account, an alias or a masked address holds the
/// address. Run before anything is applied, so a clash stops the run (and
/// `--dry-run`) with nothing written, and the assistant can ask again.
pub(in crate::cli::init) fn precheck(
	first: &FirstAccount,
	data_dir: &Path,
	config_path: &Path,
) -> Result<(), String> {
	// The store is opened from `data_dir` whether or not the configuration
	// exists or loads: a lost or unreadable config must not hide the
	// accounts already on disk. A config that loads gives its accounts
	// normalised and with `${VAR}` expanded; the raw file is only the
	// fallback when it does not load.
	let (domain_aliases, statics, aliases) = match Config::load(config_path) {
		Ok(config) => (
			config.domain_aliases.clone(),
			static_pairs(&config),
			config
				.alias
				.iter()
				.map(|alias| alias.address.clone())
				.collect(),
		),
		Err(_) => (
			Default::default(),
			static_accounts_of(config_path),
			static_aliases_of(config_path),
		),
	};
	let store = AccountStore::open(data_dir, Vec::new(), domain_aliases, Vec::new())
		.map_err(|error| format!("opening the account store: {error}"))?;
	let name = first.name();
	let address = first.stored_address();
	name_is_free_or_ours(&name, &address, &store, &statics)?;
	address_is_free_or_ours(Some(&name), &address, &store, &statics, &aliases)
}

/// The static accounts of a loaded configuration as name and addresses.
pub(super) fn static_pairs(config: &Config) -> Vec<(String, Vec<String>)> {
	config
		.accounts
		.iter()
		.map(|account| (account.name.clone(), account.addresses.clone()))
		.collect()
}

/// Whether the account already named `name` is the one `address` asks for.
/// An account with that name but other addresses is a collision, such as
/// `torre.control` and `torre-control` both giving `torre-control`: it is
/// refused instead of being skipped as if it were the same account.
pub(super) fn name_holder(
	name: &str,
	address: &str,
	holder_addresses: &[String],
) -> Result<bool, String> {
	let wanted = normalize(address);
	if holder_addresses
		.iter()
		.any(|existing| normalize(existing) == wanted)
	{
		return Ok(true);
	}
	Err(format!(
		"the account name \"{name}\" is already used by the account with the address {}, \
		 and {address} would get the same name; use another address",
		holder_addresses.join(", ")
	))
}
