//! Publishing the new keys' records and waiting until a resolver shows them.
//!
//! Signing switches to a new key only after this: a domain that signs with a
//! key nobody can look up fails DKIM on every message.

use std::time::Duration;

use crate::dkim::domain_keys::DomainKeys;
use crate::dkim::{Signer, rsa_record_value};
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};
use crate::spf::DnsLookup;

/// One TXT record a new key is published as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
	pub domain: String,
	pub name: String,
	pub value: String,
}

/// The records `keys` is published as at `domain`, ed25519 first.
pub(super) fn records(domain: &str, keys: &DomainKeys) -> Result<Vec<Record>, String> {
	let ed = Signer::load(&keys.selector, &keys.key_file)
		.map_err(|error| format!("{} does not load: {error}", keys.key_file.display()))?;
	let mut found = vec![Record {
		domain: domain.to_string(),
		name: format!("{}._domainkey.{domain}", keys.selector),
		value: ed.dns_record_value(),
	}];
	if let Some((selector, file)) = &keys.rsa {
		let value = rsa_record_value(file)
			.map_err(|error| format!("{} does not load: {error}", file.display()))?;
		found.push(Record {
			domain: domain.to_string(),
			name: format!("{selector}._domainkey.{domain}"),
			value,
		});
	}
	Ok(found)
}

/// Whether `name` is `zone` or a name below it, without regard to case.
pub(super) fn in_zone(name: &str, zone: &str) -> bool {
	crate::dkim::Rotator::is_in_zone(name, zone)
}

/// The zone whose provider writes `name`: the `[dns]` entry that serves it,
/// when it is a real provider and the name lies inside its zone. `None` means
/// the record is the operator's to publish by hand.
pub(super) fn zone_of(config: &crate::config::Config, name: &str) -> Option<String> {
	config
		.dns
		.entry_for(name)
		.filter(|dns| !dns.provider.eq_ignore_ascii_case("manual"))
		.filter(|dns| in_zone(name, &dns.zone))
		.map(|dns| dns.zone.clone())
}

/// Upsert each record into its zone. Every record is tried; the failures come
/// back named, so the operator sees all of them at once.
pub(super) async fn publish(
	provider: &dyn DnsProvider,
	records: &[(String, Record)],
) -> Vec<String> {
	let mut failed = Vec::new();
	for (zone, record) in records {
		let txt = DnsRecord {
			name: record.name.clone(),
			kind: RecordKind::Txt,
			value: record.value.clone(),
			ttl: 300,
			proxied: None,
		};
		if let Err(error) = provider.upsert(zone, txt).await {
			failed.push(format!("{}: {error}", record.name));
		}
	}
	failed
}

/// What the resolver answered for the name of a record it does not show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Answer {
	/// Nothing at that name: the resolver holds a negative answer for it.
	Nothing,
	/// Other values at that name, but not this key.
	Others,
	/// No answer at all: the lookup failed.
	Failed,
}

/// A record the resolver does not show, and what it answered instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Missing {
	/// The record that does not show.
	pub record: Record,
	/// What the resolver answered for its name.
	pub answer: Answer,
}

/// The records `resolver` does not show with the right key, after one query
/// and one more after each of `waits`. Empty when every record is visible.
pub(super) async fn missing(
	resolver: &dyn DnsLookup,
	records: &[Record],
	waits: &[Duration],
) -> Vec<Missing> {
	let mut waits = waits.iter();
	loop {
		let mut absent = Vec::new();
		for record in records {
			let (seen, answer) = match resolver.txt(&record.name).await {
				Ok(values) => {
					let seen = values.iter().any(|value| {
						crate::dkim::key_record::same_usable_key(value, &record.value)
					});
					let answer = if values.is_empty() {
						Answer::Nothing
					} else {
						Answer::Others
					};
					(seen, answer)
				}
				Err(_) => (false, Answer::Failed),
			};
			if !seen {
				absent.push(Missing {
					record: record.clone(),
					answer,
				});
			}
		}
		match (absent.is_empty(), waits.next()) {
			(true, _) | (false, None) => return absent,
			(false, Some(wait)) => tokio::time::sleep(*wait).await,
		}
	}
}
