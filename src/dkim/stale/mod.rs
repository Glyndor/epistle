//! Records of the shared `[dkim]` key that are still published at a domain
//! that has a key of its own.
//!
//! After `epistle dkim split` the moved domains sign with their own keys, but
//! the records the shared key was published under at those domains are still
//! in DNS. Whoever holds that key can still sign as those domains, and a
//! receiver finds a valid key, until the records are removed. They are the
//! selectors the default key uses (the configured pair, the one in service, the
//! one a rotation retires) at every domain with a `[[dkim.domain]]` entry,
//! minus the selectors that entry uses itself. The domain that keeps the
//! `[dkim]` key has no entry, so its records are never in this list.

use std::collections::BTreeSet;

use crate::config::Config;
use crate::spf::DnsLookup;

/// One record to retire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stale {
	/// The domain that has a key of its own.
	pub domain: String,
	/// The default key's selector.
	pub selector: String,
	/// `selector._domainkey.domain`.
	pub name: String,
}

/// Every selector the `[dkim]` key is or was published under.
fn default_selectors(config: &Config) -> Result<BTreeSet<String>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(BTreeSet::new());
	};
	let mut found = BTreeSet::new();
	found.insert(dkim.selector.to_ascii_lowercase());
	found.extend(dkim.rsa_selector.iter().map(|s| s.to_ascii_lowercase()));
	let active =
		super::rotate::active_ed25519(dkim, &config.data_dir).map_err(|error| error.to_string())?;
	found.insert(active.selector.to_ascii_lowercase());
	if let Some(rsa) =
		super::rotate::active_rsa(dkim, &config.data_dir).map_err(|error| error.to_string())?
	{
		found.insert(rsa.selector.to_ascii_lowercase());
	}
	if let Some(previous) = super::rotate::read_state(&config.data_dir)
		.map_err(|error| error.to_string())?
		.and_then(|state| state.previous)
	{
		found.insert(previous.selector.to_ascii_lowercase());
		found.extend(previous.rsa.map(|rsa| rsa.selector.to_ascii_lowercase()));
	}
	Ok(found)
}

/// The default key's records at `domain`, which signs with the selectors in
/// `own`.
pub fn names_for(config: &Config, domain: &str, own: &[String]) -> Result<Vec<Stale>, String> {
	let domain = domain.to_ascii_lowercase();
	Ok(default_selectors(config)?
		.into_iter()
		.filter(|selector| !own.iter().any(|o| o.eq_ignore_ascii_case(selector)))
		.map(|selector| Stale {
			name: format!("{selector}._domainkey.{domain}"),
			domain: domain.clone(),
			selector,
		})
		.collect())
}

/// The default key's records at every domain that has a key of its own.
pub fn names(config: &Config) -> Result<Vec<Stale>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let mut all = Vec::new();
	for entry in &dkim.domain {
		let mut own = vec![entry.selector.clone()];
		own.extend(entry.rsa_selector.clone());
		all.extend(names_for(config, &entry.name, &own)?);
	}
	Ok(all)
}

/// The ones of `candidates` that a resolver shows as a DKIM record.
pub async fn published(dns: &dyn DnsLookup, candidates: Vec<Stale>) -> Vec<Stale> {
	let mut found = Vec::new();
	for candidate in candidates {
		let seen = match dns.txt(&candidate.name).await {
			Ok(values) => values
				.iter()
				.any(|v| v.trim_start().to_ascii_lowercase().starts_with("v=dkim1")),
			Err(_) => false,
		};
		if seen {
			found.push(candidate);
		}
	}
	found
}

#[cfg(test)]
mod tests;
