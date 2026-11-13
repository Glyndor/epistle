//! The key each domain signs with, and the comparison of a published record with it.

use crate::config::Config;
use crate::spf::DnsLookup;

use super::KeyView;

/// The key each signing domain uses and the domains it shares it with.
pub(super) fn key_views(
	config: &Config,
	dkim: &crate::config::Dkim,
	default: (&str, Option<&str>),
	own: &OwnKeys,
) -> Vec<KeyView> {
	let on_default = dkim.domains_on_default(&config.domains, &config.domain_aliases);
	signing_domains(config)
		.into_iter()
		.map(|domain| match own.get(&domain) {
			Some(active) => KeyView {
				source: "dkim.domain",
				selector: active.ed.selector.clone(),
				rsa_selector: active.rsa.as_ref().map(|rsa| rsa.selector.clone()),
				shared_with: Vec::new(),
				domain,
			},
			None => KeyView {
				source: "dkim",
				selector: default.0.to_string(),
				rsa_selector: default.1.map(str::to_string),
				shared_with: on_default
					.iter()
					.filter(|d| **d != domain)
					.cloned()
					.collect(),
				domain,
			},
		})
		.collect()
}

/// The keys in service of every domain with a `[[dkim.domain]]` entry, by
/// lowercase domain: the ones its rotation put in service, or the entry's.
pub(super) type OwnKeys =
	std::collections::HashMap<String, crate::dkim::domain_rotate::DomainActive>;

pub(super) fn own_keys(config: &Config, dkim: &crate::config::Dkim) -> Result<OwnKeys, String> {
	dkim.domain
		.iter()
		.map(|entry| {
			let active = crate::dkim::domain_rotate::active_keys(entry, &config.data_dir)
				.map_err(|error| format!("{}: {error}", entry.name))?;
			Ok((entry.name.to_ascii_lowercase(), active))
		})
		.collect()
}

/// Every domain the relay signs for, lowercase and sorted.
pub(in crate::cli::dkim) fn signing_domains(config: &Config) -> Vec<String> {
	let mut all = std::collections::BTreeSet::new();
	all.extend(config.domains.iter().map(|d| d.to_ascii_lowercase()));
	all.extend(config.domain_aliases.keys().map(|d| d.to_ascii_lowercase()));
	all.into_iter().collect()
}

/// The `p=` tag of a DKIM record with whitespace removed.
pub(super) fn public_key(record: &str) -> Option<String> {
	record
		.split(';')
		.find_map(|tag| tag.trim().strip_prefix("p="))
		.map(|value| value.split_whitespace().collect())
}

/// Compare the TXT records at `name` with `expected` (a full record value;
/// `None` means only presence of a DKIM record is checked).
pub(super) async fn compare(
	dns: &dyn DnsLookup,
	name: &str,
	expected: Option<&str>,
) -> &'static str {
	let Ok(records) = dns.txt(name).await else {
		return "lookup-error";
	};
	let dkim: Vec<&String> = records
		.iter()
		.filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dkim1"))
		.collect();
	if dkim.is_empty() {
		return "missing";
	}
	match expected.and_then(public_key) {
		Some(want) if !dkim.iter().any(|r| public_key(r).as_deref() == Some(&want)) => "differs",
		_ => "ok",
	}
}
