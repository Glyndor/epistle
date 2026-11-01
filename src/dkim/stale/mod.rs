//! Records of the shared `[dkim]` key that are still published at a domain
//! that has a key of its own.
//!
//! After `epistle dkim split` the moved domains sign with their own keys, but
//! the records the shared key was published under at those domains are still
//! in DNS. Whoever holds that key can still sign as those domains, and a
//! receiver finds a valid key, until the records are removed.
//!
//! A record is the shared key's only when its `p=` is the public key of a key
//! the server knows is the shared one (the configured pair, the one in service,
//! the one a rotation retires). Anything else at the same name is somebody
//! else's and is reported, never touched. A lookup that fails, or a record with
//! no `p=` to compare, is "unknown", never "gone": nothing here treats a
//! failure as a finished split.

use std::collections::BTreeMap;

use crate::config::Config;
use crate::spf::DnsLookup;

/// One record the shared key may still be published as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stale {
	/// The domain that has a key of its own.
	pub domain: String,
	/// The shared key's selector.
	pub selector: String,
	/// `selector._domainkey.domain`.
	pub name: String,
	/// The public key (`p=`) the shared key publishes under this selector;
	/// `None` when its key file is gone, which makes a record at the name
	/// unverifiable.
	pub expected: Option<String>,
}

/// What a lookup found at a [`Stale`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
	/// The shared key is published here; the exact record value.
	Shared(String),
	/// Nothing is published here.
	Absent,
	/// A record is here that is not the shared key's, or cannot be shown to
	/// be: left alone.
	NotOurs(String),
	/// The answer could not be read, so nothing can be said.
	Unknown(String),
}

/// The `p=` value of a DKIM record, whitespace removed.
pub fn public_part(record: &str) -> Option<String> {
	record.split(';').find_map(|tag| {
		let (name, value) = tag.split_once('=')?;
		(name.trim() == "p").then(|| value.chars().filter(|c| !c.is_whitespace()).collect())
	})
}

/// Every selector the `[dkim]` key is or was published under, with the public
/// key it publishes there.
fn default_selectors(config: &Config) -> Result<BTreeMap<String, Option<String>>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(BTreeMap::new());
	};
	let ed = |selector: &str, file: &std::path::Path| {
		super::Signer::load(selector, file)
			.ok()
			.and_then(|signer| public_part(&signer.dns_record_value()))
	};
	let rsa = |file: &std::path::Path| {
		super::rsa_record_value(file)
			.ok()
			.and_then(|record| public_part(&record))
	};
	let mut found: BTreeMap<String, Option<String>> = BTreeMap::new();
	let mut add = |selector: &str, public: Option<String>| {
		let slot = found.entry(selector.to_ascii_lowercase()).or_default();
		if slot.is_none() {
			*slot = public;
		}
	};
	add(&dkim.selector, ed(&dkim.selector, &dkim.key_file));
	if let (Some(selector), Some(file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
		add(selector, rsa(file));
	}
	let active =
		super::rotate::active_ed25519(dkim, &config.data_dir).map_err(|error| error.to_string())?;
	add(&active.selector, ed(&active.selector, &active.key_file));
	if let Some(key) =
		super::rotate::active_rsa(dkim, &config.data_dir).map_err(|error| error.to_string())?
	{
		add(&key.selector, rsa(&key.key_file));
	}
	if let Some(previous) = super::rotate::read_state(&config.data_dir)
		.map_err(|error| error.to_string())?
		.and_then(|state| state.previous)
	{
		let file = config.data_dir.join(&previous.key_file);
		add(&previous.selector, ed(&previous.selector, &file));
		if let Some(old) = previous.rsa {
			add(&old.selector, rsa(&config.data_dir.join(&old.key_file)));
		}
	}
	Ok(found)
}

/// The default key's records at `domain`, which signs with the selectors in
/// `own`.
pub fn names_for(config: &Config, domain: &str, own: &[String]) -> Result<Vec<Stale>, String> {
	let domain = domain.to_ascii_lowercase();
	Ok(default_selectors(config)?
		.into_iter()
		.filter(|(selector, _)| !own.iter().any(|o| o.eq_ignore_ascii_case(selector)))
		.map(|(selector, expected)| Stale {
			name: format!("{selector}._domainkey.{domain}"),
			domain: domain.clone(),
			selector,
			expected,
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

/// What is published at `candidate`.
pub async fn presence(dns: &dyn DnsLookup, candidate: &Stale) -> Presence {
	let values = match dns.txt(&candidate.name).await {
		Ok(values) => values,
		Err(_) => return Presence::Unknown(format!("the lookup of {} failed", candidate.name)),
	};
	if values.is_empty() {
		return Presence::Absent;
	}
	let mut other = None;
	for value in &values {
		match (public_part(value), &candidate.expected) {
			(Some(p), Some(expected)) if p == *expected => return Presence::Shared(value.clone()),
			(Some(_), Some(_)) => other = Some("it publishes another key".to_string()),
			(Some(_), None) => {
				other = Some("the key it would be is not on this host to compare".to_string());
			}
			(None, _) => {
				return Presence::Unknown(format!(
					"{} has a record with no p= tag to compare",
					candidate.name
				));
			}
		}
	}
	Presence::NotOurs(other.unwrap_or_default())
}

/// The outcome of looking at a list of candidates.
#[derive(Debug, Default)]
pub struct Survey {
	/// Where the shared key is published, with the exact record value.
	pub shared: Vec<(Stale, String)>,
	/// Records that are not the shared key's, with why.
	pub not_ours: Vec<(Stale, String)>,
	/// Names that could not be read, with why.
	pub unknown: Vec<(Stale, String)>,
}

/// Look at every candidate.
pub async fn survey(dns: &dyn DnsLookup, candidates: Vec<Stale>) -> Survey {
	let mut found = Survey::default();
	for candidate in candidates {
		match presence(dns, &candidate).await {
			Presence::Shared(value) => found.shared.push((candidate, value)),
			Presence::Absent => {}
			Presence::NotOurs(why) => found.not_ours.push((candidate, why)),
			Presence::Unknown(why) => found.unknown.push((candidate, why)),
		}
	}
	found
}

#[cfg(test)]
mod tests;
