//! Whether `postmaster@` of every served domain reaches someone.
//!
//! RFC 5321 section 4.5.1 requires a server to accept mail for `postmaster`
//! at every domain it serves. `Config::validate` logs the same check from
//! `serve`, but it sees only the accounts in the file; this one also reads
//! the accounts `epistle account add` keeps in the data directory and the
//! `[[alias]]` tables, so `config-check` can say it before mail bounces.

use std::collections::HashSet;

use crate::config::Config;
use crate::directory_store::AccountStore;

/// The configured domains whose `postmaster@` is no account's address, no
/// alias and no account's catch-all. Empty when the server has no account
/// at all (it has nobody to deliver to anyway) or when the account store
/// cannot be read, so the check never invents a problem it cannot see.
pub(super) fn missing_postmaster(config: &Config) -> Vec<String> {
	let Ok(store) = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) else {
		return Vec::new();
	};
	let views = store.account_views();
	if views.is_empty() {
		return Vec::new();
	}
	let mut reached: HashSet<String> = views
		.iter()
		.flat_map(|(_, addresses, _)| addresses.iter().map(|a| a.to_ascii_lowercase()))
		.chain(
			config
				.alias
				.iter()
				.map(|alias| alias.address.to_ascii_lowercase()),
		)
		.collect();
	let catch_all = config
		.accounts
		.iter()
		.flat_map(|account| account.catch_all.clone())
		.chain(
			views
				.iter()
				.filter_map(|(name, _, _)| store.dynamic(name))
				.flat_map(|account| account.catch_all),
		);
	for domain in catch_all {
		reached.insert(format!("postmaster@{}", domain.to_ascii_lowercase()));
	}
	config
		.domains
		.iter()
		.filter(|domain| !reached.contains(&format!("postmaster@{}", domain.to_ascii_lowercase())))
		.cloned()
		.collect()
}
