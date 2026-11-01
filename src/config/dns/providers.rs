//! The `dns` key of the configuration: one `[dns]` table, or several
//! `[[dns]]` tables, each with its own credential and the zone it reaches.

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use super::{Dns, SUPPORTED_PROVIDERS, is_supported_provider};
use crate::config::{ConfigError, validate_dns_name};
use crate::dns::provider::DnsProvider;
use crate::dns::router::{ZoneRouter, contains, normalize};

/// Every DNS provider entry, in the order the file lists them.
///
/// A configuration with a single `[dns]` table holds one entry and behaves as
/// it always did. Several `[[dns]]` tables hold one credential each; a name is
/// served by the entry whose zone is the longest one containing it.
///
/// What the file used decides the rules: a `[dns]` table keeps the lone-entry
/// behaviour, and any `[[dns]]` list, even of one element, is scoped to the
/// zones it names.
#[derive(Clone, Default)]
pub struct DnsProviders {
	entries: Vec<Dns>,
	list: bool,
}

impl DnsProviders {
	/// A set of entries written as `[[dns]]` tables, in file order.
	pub fn new(entries: Vec<Dns>) -> Self {
		DnsProviders {
			entries,
			list: true,
		}
	}

	/// Whether the entries came from `[[dns]]` tables. A scoped set serves
	/// only the zones it names and takes the strict validation, whatever its
	/// length; a lone `[dns]` table serves every name, as it always did.
	pub fn scoped(&self) -> bool {
		self.list
	}

	/// The entries in file order.
	pub fn iter(&self) -> std::slice::Iter<'_, Dns> {
		self.entries.iter()
	}

	/// Whether no `[dns]` entry is configured.
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	/// How many entries are configured.
	pub fn len(&self) -> usize {
		self.entries.len()
	}

	/// The first entry. Only the places that describe a single `[dns]`
	/// section (the `init` wizard) use it; everything that writes DNS goes
	/// through [`Self::entry_for`] or [`Self::build_for_host`].
	pub fn first(&self) -> Option<&Dns> {
		self.entries.first()
	}

	/// The entry configured for exactly `zone`.
	pub fn for_zone(&self, zone: &str) -> Option<&Dns> {
		let zone = normalize(zone);
		self.entries.iter().find(|dns| normalize(&dns.zone) == zone)
	}

	/// The entry that serves `name`: the one with the longest zone that
	/// contains it. A configuration with a single entry serves every name
	/// with it, as a lone `[dns]` always did; with several entries a name
	/// outside all of them has no provider and falls back to manual.
	pub fn entry_for(&self, name: &str) -> Option<&Dns> {
		if let [only] = self.entries.as_slice()
			&& !self.list
		{
			return Some(only);
		}
		let name = normalize(name);
		self.entries
			.iter()
			.filter(|dns| contains(&normalize(&dns.zone), &name))
			.max_by_key(|dns| normalize(&dns.zone).len())
	}

	/// Whether `name` has an entry that can publish: one that is not
	/// `manual`.
	pub fn publishes(&self, name: &str) -> bool {
		self.entry_for(name)
			.is_some_and(|dns| !dns.provider.eq_ignore_ascii_case("manual"))
	}

	/// The zones the entries are scoped to, in file order.
	pub fn zones(&self) -> Vec<String> {
		self.entries.iter().map(|dns| dns.zone.clone()).collect()
	}

	/// Reject what the build cannot use. A `provider` the build does not know
	/// is refused: without this, a typo like `provider = "cloudfare"` falls
	/// through `Dns::build` to the manual arm and the operator's automation
	/// silently never runs. With several entries the zone is what tells them
	/// apart, so each needs a real name and no two may claim the same zone:
	/// the second would never be reached, and the operator would believe its
	/// credential was in use.
	pub(crate) fn validate(&self) -> Result<(), ConfigError> {
		let mut zones = std::collections::HashSet::new();
		for dns in &self.entries {
			if !is_supported_provider(&dns.provider) {
				return Err(ConfigError::Invalid(format!(
					"[dns] provider {:?} is not a supported provider; supported: {}",
					dns.provider,
					SUPPORTED_PROVIDERS.join(", "),
				)));
			}
			if self.list {
				validate_dns_name("[[dns]] zone", &dns.zone)?;
				if !zones.insert(normalize(&dns.zone)) {
					return Err(ConfigError::Invalid(format!(
						"[[dns]] zone {} appears twice; each zone has one provider and one credential",
						dns.zone
					)));
				}
			}
		}
		Ok(())
	}

	/// One provider for every entry, or `None` when nothing can publish.
	///
	/// A single entry builds the provider it always built. Several entries
	/// build a [`ZoneRouter`]: each zone reaches its own credential, an entry
	/// that is `manual` or whose credential cannot be read still owns its zone
	/// and writes nothing, and a zone outside every entry is refused. `None`
	/// when no entry can build a provider, like a lone `manual`.
	pub fn build_for_host(&self, hostname: &str) -> Option<Arc<dyn DnsProvider>> {
		if let [only] = self.entries.as_slice()
			&& !self.list
		{
			return only.build_for_host(hostname);
		}
		let mut any = false;
		let routes = self
			.entries
			.iter()
			.map(|dns| {
				let built = dns.build_for_host(hostname);
				any |= built.is_some();
				let provider: Arc<dyn DnsProvider> =
					built.unwrap_or_else(|| Arc::new(crate::dns::provider::ManualProvider));
				(dns.zone.clone(), provider)
			})
			.collect();
		any.then(|| Arc::new(ZoneRouter::new(routes)) as Arc<dyn DnsProvider>)
	}
}

impl<'a> IntoIterator for &'a DnsProviders {
	type Item = &'a Dns;
	type IntoIter = std::slice::Iter<'a, Dns>;
	fn into_iter(self) -> Self::IntoIter {
		self.entries.iter()
	}
}

impl From<Dns> for DnsProviders {
	fn from(dns: Dns) -> Self {
		DnsProviders {
			entries: vec![dns],
			list: false,
		}
	}
}

impl fmt::Debug for DnsProviders {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_list().entries(&self.entries).finish()
	}
}

impl<'de> Deserialize<'de> for DnsProviders {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Entries;

		impl<'de> Visitor<'de> for Entries {
			type Value = DnsProviders;

			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("a [dns] table or a list of [[dns]] tables")
			}

			fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
				let dns = Dns::deserialize(de::value::MapAccessDeserializer::new(map))?;
				Ok(DnsProviders::from(dns))
			}

			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
				let mut entries = Vec::new();
				while let Some(dns) = seq.next_element::<Dns>()? {
					entries.push(dns);
				}
				Ok(DnsProviders::new(entries))
			}
		}

		deserializer.deserialize_any(Entries)
	}
}
