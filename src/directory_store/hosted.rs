//! The hosted domains the account store builds every directory with, and
//! their replacement when the domain state file is reloaded.

use std::collections::HashMap;

use super::AccountStore;

/// The hosted domains, the domain aliases and the domains that are switched
/// off or only receive, as the directory needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedDomains {
	/// The hosted domains.
	pub domains: Vec<String>,
	/// The server's own name, which need not be a hosted domain.
	pub hostname: String,
	/// Alias domain to hosted domain.
	pub domain_aliases: HashMap<String, String>,
	/// Hosted domains that are switched off.
	pub disabled: Vec<String>,
	/// Hosted domains nobody may send as (`receive_only_domains`).
	pub send_off: Vec<String>,
	/// Per-domain storage quota overrides, reloaded with the domains.
	pub domain_quotas: HashMap<String, u64>,
	/// Per-domain submission-rate overrides, reloaded with the domains.
	pub domain_submission_limits: HashMap<String, u32>,
}

impl HostedDomains {
	/// The hosted domains of `config`.
	pub fn of(config: &crate::config::Config) -> Self {
		HostedDomains {
			domains: config.domains.clone(),
			hostname: config.hostname.clone(),
			domain_aliases: config.domain_aliases.clone(),
			disabled: config.disabled_domains.clone(),
			send_off: config.receive_only_domains.clone(),
			domain_quotas: config.domain_quotas.clone(),
			domain_submission_limits: config.domain_submission_limits.clone(),
		}
	}
}

impl AccountStore {
	/// The hosted domains the store builds the directory with now.
	pub fn hosted_domains(&self) -> HostedDomains {
		self.hosted.read().expect("hosted lock").clone()
	}

	/// Whether `domain` is hosted, without regard to ASCII case.
	pub(super) fn hosts(&self, domain: &str) -> bool {
		self.hosted
			.read()
			.expect("hosted lock")
			.domains
			.iter()
			.any(|hosted| hosted.eq_ignore_ascii_case(domain))
	}

	/// Replace the hosted domains with `hosted` and rebuild the directory, so
	/// the next recipient, sender or login check sees them. Called when the
	/// domain state file changes; nothing is written.
	pub fn reload_domains(&self, hosted: HostedDomains) {
		{
			let mut current = self.hosted.write().expect("hosted lock");
			if *current == hosted {
				return;
			}
			*current = hosted;
		}
		self.handle.replace(self.build_directory());
	}
}
