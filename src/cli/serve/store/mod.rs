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
	if let Some(notice) = masked_off_notice(config.masked_addresses_max) {
		tracing::warn!("{notice}");
	}
	Ok(AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| std::io::Error::other(error.to_string()))?
	.with_server_name(config.hostname.clone())
	.with_disabled_domains(config.disabled_domains.clone())
	.with_send_off_domains(config.receive_only_domains.clone())
	.with_domain_quotas(config.domain_quotas.clone())
	.with_domain_submission_limits(config.domain_submission_limits.clone())
	.with_aliases(config.alias.clone())
	.with_masked_max(config.masked_addresses_max)
	.with_limits(crate::limits::Limits::shared(config)))
}

/// What to tell the operator when `masked_addresses_max` is 0. An older
/// release read 0 as "no cap"; it now turns masked addresses off, so a
/// config written for the old meaning would lose the feature without a word.
fn masked_off_notice(max: usize) -> Option<&'static str> {
	(max == 0).then_some(
		"masked_addresses_max = 0 turns masked addresses off: every request to create one is refused. Releases before this one read 0 as no limit; remove the line for the default of 100, or set the number you want",
	)
}

#[cfg(test)]
mod tests;
