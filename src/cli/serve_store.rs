//! The account store `serve` opens from the static config. Its own function
//! so the submission-limit regression tests open the store exactly the way
//! the server does: the per-domain submission limits once went missing from
//! this chain (#802) and nothing noticed.

use crate::config::Config;
use crate::directory_store::AccountStore;

/// Open the account store for `config`: the static accounts, domains and
/// aliases, with the disabled domains, the per-domain quotas and the
/// per-domain submission limits that every directory rebuilt from it carries.
pub(super) fn open_account_store(config: &Config) -> std::io::Result<AccountStore> {
	Ok(AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| std::io::Error::other(error.to_string()))?
	.with_disabled_domains(config.disabled_domains.clone())
	.with_domain_quotas(config.domain_quotas.clone())
	.with_domain_submission_limits(config.domain_submission_limits.clone())
	.with_aliases(config.alias.clone())
	.with_masked_max(config.masked_addresses_max))
}

#[cfg(test)]
#[path = "serve_store_tests.rs"]
mod tests;
