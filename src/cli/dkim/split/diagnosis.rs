//! Why a record the host's resolver does not show is not showing.
//!
//! The wait ends with records still missing, and "not visible yet" alone
//! leaves the operator with two hypotheses that need opposite actions: the
//! publish never reached the zone, or the zone serves the record and the
//! host's resolver is holding a cached negative answer (RFC 2308 section 5).
//! The zone's own nameservers tell the two apart: they are asked directly,
//! with no cache in between, and what they answer is the zone's.
//!
//! The verdict names the cause and nothing else. Signing still switches only
//! when the host's resolver shows the record, as before: the split waits for
//! the resolver the host itself uses, and the report says why the resolver
//! does not show the record.

use crate::dns::authoritative::AuthorityLookup;
use crate::spf::DnsLookup;

use super::publish::{Answer, Missing};

/// Why a record the host's resolver does not show is not showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Cause {
	/// The zone's authoritative servers publish it and the host's resolver
	/// holds a negative answer for the name.
	CachedNegative {
		/// The seconds the cached negative answer is good for, when the
		/// resolver says.
		ttl: Option<u32>,
	},
	/// The zone's authoritative servers publish it and the host's resolver
	/// does not show it: it answers something else, or it cannot answer.
	NotShown,
	/// Some of the zone's authoritative servers publish it and others do
	/// not: the zone is still propagating.
	PartlyServed,
	/// No authoritative server publishes it: the zone does not serve it.
	NotServed,
	/// The zone's authoritative servers could not be asked.
	Unknown,
}

impl Cause {
	/// The value of the `cause` field in the JSON result.
	pub(super) fn name(&self) -> &'static str {
		match self {
			Cause::CachedNegative { .. } => "cached-negative",
			Cause::NotShown => "not-shown",
			Cause::PartlyServed => "partly-served",
			Cause::NotServed => "not-served",
			Cause::Unknown => "unknown",
		}
	}

	/// The line that tells the operator what the state means.
	pub(super) fn explanation(&self) -> String {
		match self {
			Cause::CachedNegative { ttl: Some(ttl) } => format!(
				"the zone's authoritative servers publish it; the host's resolver holds a cached negative answer (good for up to {ttl} s)"
			),
			Cause::CachedNegative { ttl: None } => "the zone's authoritative servers publish it; the host's resolver holds a cached negative answer".to_string(),
			Cause::NotShown => "the zone's authoritative servers publish it; the host's resolver does not show it".to_string(),
			Cause::PartlyServed => "the zone's authoritative servers do not agree: some publish it and the rest do not answer with it".to_string(),
			Cause::NotServed => "no authoritative server of the zone publishes it: the record has not reached the zone".to_string(),
			Cause::Unknown => "the zone's authoritative servers could not be asked, so the reason is unknown".to_string(),
		}
	}

	/// The seconds the negative answer is good for, when the cause is a
	/// cached one.
	pub(super) fn ttl(&self) -> Option<u32> {
		match self {
			Cause::CachedNegative { ttl } => *ttl,
			_ => None,
		}
	}
}

/// What the zone's authoritative servers say about one record the host's
/// resolver does not show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Diagnosis {
	/// The name of the record.
	pub name: String,
	/// Why it does not show up.
	pub cause: Cause,
}

/// What the zone's authoritative servers say about every record the host's
/// resolver does not show, with the cause each one has.
pub(super) async fn diagnose(
	missing: &[Missing],
	resolver: &dyn DnsLookup,
	authority: Option<&dyn AuthorityLookup>,
) -> Vec<Diagnosis> {
	let mut diagnoses = Vec::new();
	for entry in missing {
		let cause = cause_of(entry, resolver, authority).await;
		diagnoses.push(Diagnosis {
			name: entry.record.name.clone(),
			cause,
		});
	}
	diagnoses
}

/// The cause of one record the host's resolver does not show.
async fn cause_of(
	entry: &Missing,
	resolver: &dyn DnsLookup,
	authority: Option<&dyn AuthorityLookup>,
) -> Cause {
	let Some(authority) = authority else {
		return Cause::Unknown;
	};
	let Some(answer) = authority.txt(&entry.record.name).await else {
		return Cause::Unknown;
	};
	let record = &entry.record;
	let same = |served: &str| crate::dkim::key_record::same_usable_key(served, &record.value);
	if answer.all_serve(same) {
		// The zone serves it. What keeps the host from seeing it is the
		// answer its resolver holds, and only a resolver that answered
		// "nothing there" holds a negative one.
		return match entry.answer {
			Answer::Nothing => Cause::CachedNegative {
				ttl: resolver.negative_ttl(&record.name).await.unwrap_or(None),
			},
			Answer::Others | Answer::Failed => Cause::NotShown,
		};
	}
	if answer.any_serve(same) {
		return Cause::PartlyServed;
	}
	// A server that did not answer proves nothing: the zone may still serve
	// the record on it.
	if answer.silent > 0 {
		return Cause::Unknown;
	}
	Cause::NotServed
}
