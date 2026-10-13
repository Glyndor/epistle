//! What the picker offers: the accounts, aliases, domains and labels that
//! exist, read the way the command itself would read them.

use std::path::Path;

use super::target::Kind;
use crate::api::ApiKeyStore;
use crate::config::Config;
use crate::directory_store::{AccountStore, AppPasswordStore};

/// Every value of `kind` the configuration at `config` knows, sorted. An
/// error (the file does not load, a store does not open) means there is
/// nothing to offer, and the usage error stands.
pub(super) fn list(kind: &Kind, config: &Path) -> Result<Vec<String>, String> {
	let config = Config::load(config).map_err(|error| error.to_string())?;
	let mut values: Vec<String> = match kind {
		Kind::Account => AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			config.domain_aliases.clone(),
			config.accounts.clone(),
		)
		.map_err(|error| error.to_string())?
		.account_views()
		.into_iter()
		.map(|(name, _, _)| name)
		.collect(),
		Kind::Alias => config
			.alias
			.iter()
			.map(|alias| alias.address.clone())
			.collect(),
		Kind::Domain => config.domains.clone(),
		Kind::AppPassword(account) => AppPasswordStore::open(&config.data_dir)
			.map_err(|error| error.to_string())?
			.list()
			.into_iter()
			.filter(|(owner, ..)| owner.eq_ignore_ascii_case(account))
			.map(|(_, label, ..)| label)
			.collect(),
		Kind::ApiKey => ApiKeyStore::open(&config.data_dir)
			.map_err(|error| error.to_string())?
			.list()
			.into_iter()
			.map(|key| key.label)
			.collect(),
	};
	if !matches!(kind, Kind::Domain | Kind::Alias) {
		values.sort();
	}
	Ok(values)
}
