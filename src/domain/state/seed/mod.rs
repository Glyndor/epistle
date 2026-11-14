//! What the configuration file says about the hosted domains, kept aside
//! when the state file is laid over it.
//!
//! The seed is taken once, when the configuration file is loaded and before
//! [`super::overlay`] replaces the lists, so a reload of the state file starts
//! again from the same configuration-file values, and the state file made
//! from it (by the first write, the first start of `serve`, or
//! `epistle domain import`) holds exactly what the configuration file
//! declared.

use std::collections::{BTreeMap, HashMap};

use crate::config::{Config, DkimDomain, SrsDomain};

use super::file::{DomainsFile, HostedDomain, StoredRole};

/// The configuration file's own domain lists and the per-domain entries that
/// name a domain.
#[derive(Debug, Clone, Default)]
pub struct DomainSeed {
	/// Whether the seed was taken. A configuration built in code rather than
	/// loaded from a file has none, and its lists are its own.
	pub captured: bool,
	/// `domains`.
	pub domains: Vec<String>,
	/// `domain_aliases`.
	pub domain_aliases: HashMap<String, String>,
	/// `disabled_domains`.
	pub disabled_domains: Vec<String>,
	/// `send_only_domains`.
	pub send_only_domains: Vec<String>,
	/// `receive_only_domains`.
	pub receive_only_domains: Vec<String>,
	/// The `[[dkim.domain]]` entries.
	pub dkim_domains: Vec<DkimDomain>,
	/// The `[[srs_domain]]` entries.
	pub srs_domain: Vec<SrsDomain>,
	/// `domain_quotas`.
	pub domain_quotas: HashMap<String, u64>,
	/// `domain_submission_limits`.
	pub domain_submission_limits: HashMap<String, u32>,
}

impl DomainSeed {
	/// The seed of `config`, as loaded from its file.
	pub fn capture(config: &Config) -> Self {
		DomainSeed {
			captured: true,
			domains: config.domains.clone(),
			domain_aliases: config.domain_aliases.clone(),
			disabled_domains: config.disabled_domains.clone(),
			send_only_domains: config.send_only_domains.clone(),
			receive_only_domains: config.receive_only_domains.clone(),
			dkim_domains: config
				.dkim
				.as_ref()
				.map(|dkim| dkim.domain.clone())
				.unwrap_or_default(),
			srs_domain: config.srs_domain.clone(),
			domain_quotas: config.domain_quotas.clone(),
			domain_submission_limits: config.domain_submission_limits.clone(),
		}
	}

	/// The state file the configuration file's lists make: every domain of
	/// `domains` in order, with its role and switch, and every alias.
	pub fn file(&self) -> DomainsFile {
		let domains = self
			.domains
			.iter()
			.map(|name| {
				let lower = name.trim().to_ascii_lowercase();
				let role = if listed(&self.send_only_domains, &lower) {
					StoredRole::SendOnly
				} else if listed(&self.receive_only_domains, &lower) {
					StoredRole::ReceiveOnly
				} else {
					StoredRole::Full
				};
				HostedDomain {
					role,
					enabled: !listed(&self.disabled_domains, &lower),
					..HostedDomain::new(&lower)
				}
			})
			.collect();
		let aliases = self
			.domain_aliases
			.iter()
			.map(|(alias, target)| {
				(
					alias.trim().to_ascii_lowercase(),
					target.trim().to_ascii_lowercase(),
				)
			})
			.collect::<BTreeMap<_, _>>();
		DomainsFile {
			seed_digest: self.digest(),
			domains,
			aliases,
		}
	}

	/// A digest of the domains, roles, switches and aliases the configuration
	/// file declares, independent of order and ASCII case. Stored in the
	/// state file made from this seed, so a later edit of these lists in the
	/// configuration file shows as a different digest.
	pub fn digest(&self) -> String {
		let mut lines: Vec<String> = Vec::new();
		let lower = |list: &[String]| {
			let mut list: Vec<String> = list
				.iter()
				.map(|name| name.trim().to_ascii_lowercase())
				.collect();
			list.sort();
			list.dedup();
			list.join(",")
		};
		lines.push(format!("domains={}", lower(&self.domains)));
		lines.push(format!("disabled={}", lower(&self.disabled_domains)));
		lines.push(format!("send-only={}", lower(&self.send_only_domains)));
		lines.push(format!(
			"receive-only={}",
			lower(&self.receive_only_domains)
		));
		let mut aliases: Vec<String> = self
			.domain_aliases
			.iter()
			.map(|(alias, target)| {
				format!(
					"{}={}",
					alias.trim().to_ascii_lowercase(),
					target.trim().to_ascii_lowercase()
				)
			})
			.collect();
		aliases.sort();
		lines.push(format!("aliases={}", aliases.join(",")));
		let digest = ring::digest::digest(&ring::digest::SHA256, lines.join("\n").as_bytes());
		let hex: String = digest
			.as_ref()
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		format!("sha256:{hex}")
	}
}

/// Whether `name` is in `list`, without regard to ASCII case.
pub(super) fn listed(list: &[String], name: &str) -> bool {
	list.iter()
		.any(|entry| entry.trim().eq_ignore_ascii_case(name.trim()))
}

#[cfg(test)]
mod tests;
