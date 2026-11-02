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
//! the one a rotation retires). A selector can have been published with more
//! than one of those keys over time, so each selector carries the set of them.
//! Anything else at the name is somebody else's and is reported, never
//! touched. A lookup that fails, a record with no `p=` to compare, or a record
//! at a name whose shared key cannot be read on this host is "unknown", never
//! "gone" and never "not ours": nothing here treats a failure as a finished
//! split.

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
	/// The public keys (`p=`) the shared key has published under this
	/// selector, as far as this host can read them.
	pub expected: Vec<String>,
	/// Why a key that should be among those could not be read, when one could
	/// not: a record here cannot then be shown to be somebody else's.
	pub unreadable: Option<String>,
}

/// What a lookup found at a [`Stale`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
	/// The shared key is published here: every record value whose `p=` is one
	/// of its keys, and the other values at the name, which are not ours.
	Shared {
		/// The values to retire.
		shared: Vec<String>,
		/// Values of other keys at the same name.
		others: Vec<String>,
	},
	/// Nothing is published here.
	Absent,
	/// Records are here and none is the shared key's.
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

/// The public key of the key file, or why it cannot be read: a file that is
/// not on this host is told apart from one that is there and does not load.
fn public_of(
	file: &std::path::Path,
	read: impl Fn(&std::path::Path) -> Result<String, String>,
) -> Result<String, String> {
	match std::fs::metadata(file) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return Err(format!(
				"the key file {} is not on this host",
				file.display()
			));
		}
		Err(error) => return Err(format!("cannot read {}: {error}", file.display())),
		Ok(_) => {}
	}
	read(file).map_err(|error| format!("cannot read {}: {error}", file.display()))
}

#[derive(Default)]
struct Keys {
	expected: Vec<String>,
	unreadable: Option<String>,
}

/// Every selector the `[dkim]` key is or was published under, with its keys.
fn default_selectors(config: &Config) -> Result<BTreeMap<String, Keys>, String> {
	let Some(dkim) = &config.dkim else {
		return Ok(BTreeMap::new());
	};
	let ed = |selector: &str| {
		let selector = selector.to_string();
		move |file: &std::path::Path| {
			super::Signer::load(&selector, file)
				.map_err(|error| error.to_string())
				.and_then(|signer| {
					public_part(&signer.dns_record_value())
						.ok_or_else(|| "it has no public key".to_string())
				})
		}
	};
	let rsa = |file: &std::path::Path| {
		super::rsa_record_value(file)
			.map_err(|error| error.to_string())
			.and_then(|record| {
				public_part(&record).ok_or_else(|| "it has no public key".to_string())
			})
	};
	let mut found: BTreeMap<String, Keys> = BTreeMap::new();
	let mut add = |selector: &str, public: Result<String, String>| {
		let slot = found.entry(selector.to_ascii_lowercase()).or_default();
		match public {
			Ok(p) if !slot.expected.contains(&p) => slot.expected.push(p),
			Ok(_) => {}
			Err(why) => slot.unreadable = slot.unreadable.take().or(Some(why)),
		}
	};
	add(
		&dkim.selector,
		public_of(&dkim.key_file, ed(&dkim.selector)),
	);
	if let (Some(selector), Some(file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
		add(selector, public_of(file, rsa));
	}
	let active =
		super::rotate::active_ed25519(dkim, &config.data_dir).map_err(|error| error.to_string())?;
	add(
		&active.selector,
		public_of(&active.key_file, ed(&active.selector)),
	);
	if let Some(key) =
		super::rotate::active_rsa(dkim, &config.data_dir).map_err(|error| error.to_string())?
	{
		add(&key.selector, public_of(&key.key_file, rsa));
	}
	if let Some(previous) = super::rotate::read_state(&config.data_dir)
		.map_err(|error| error.to_string())?
		.and_then(|state| state.previous)
	{
		let file = config.data_dir.join(&previous.key_file);
		add(&previous.selector, public_of(&file, ed(&previous.selector)));
		if let Some(old) = previous.rsa {
			add(
				&old.selector,
				public_of(&config.data_dir.join(&old.key_file), rsa),
			);
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
		.map(|(selector, keys)| Stale {
			name: format!("{selector}._domainkey.{domain}"),
			domain: domain.clone(),
			selector,
			expected: keys.expected,
			unreadable: keys.unreadable,
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
	let (mut shared, mut others) = (Vec::new(), Vec::new());
	for value in values {
		match public_part(&value) {
			Some(p) if candidate.expected.contains(&p) => shared.push(value),
			Some(_) => others.push(value),
			None => {
				return Presence::Unknown(format!(
					"{} has a record with no p= tag to compare",
					candidate.name
				));
			}
		}
	}
	if let (false, Some(why)) = (others.is_empty(), &candidate.unreadable) {
		// A record is here and the key that would say whether it is the
		// shared one is not readable: it cannot be called somebody else's.
		return Presence::Unknown(format!("{}: {why}", candidate.name));
	}
	if shared.is_empty() {
		return Presence::NotOurs("it publishes another key".to_string());
	}
	Presence::Shared { shared, others }
}

/// A record of the shared key found at a name.
#[derive(Debug, Clone)]
pub struct Found {
	/// The name and what it is.
	pub stale: Stale,
	/// Every value of the shared key at the name.
	pub shared: Vec<String>,
	/// The other values at the name, which are not ours.
	pub others: Vec<String>,
}

/// The outcome of looking at a list of candidates.
#[derive(Debug, Default)]
pub struct Survey {
	/// Where the shared key is published.
	pub shared: Vec<Found>,
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
			Presence::Shared { shared, others } => found.shared.push(Found {
				stale: candidate,
				shared,
				others,
			}),
			Presence::Absent => {}
			Presence::NotOurs(why) => found.not_ours.push((candidate, why)),
			Presence::Unknown(why) => found.unknown.push((candidate, why)),
		}
	}
	found
}

#[cfg(test)]
mod tests;
