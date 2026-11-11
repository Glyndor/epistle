//! The null records a domain needs as a set, for the reconcile loop and for
//! `status`: the same decision `dns lockdown` makes name by name, without
//! the DMARC ramp.

use std::collections::BTreeSet;

use super::names::{self, Verdict};
use super::{
	Cuts, Journal, JournalEntry, NULL_MX, NULL_SPF, TTL, WildcardDecision, in_domain, is_null_mx,
	mx_owners, wildcard_decision,
};
use crate::dns::names::{ServedNames, canonical_name, is_valid_name};
use crate::dns::provider::{DnsRecord, RecordKind};

/// What a domain needs, and what it does not have yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NullSet {
	/// Every null record the domain wants: the ones missing and the ones
	/// `ours` already published and that still apply. A record in `ours`
	/// that is not here no longer applies, and the ledger retires it.
	pub needed: Vec<DnsRecord>,
	/// The names (and `*.<domain>`) that lack a null record: what is not
	/// covered yet.
	pub uncovered: Vec<String>,
}

/// The null records `domain` needs in `zone`, read from `existing`.
///
/// `ours` are the records epistle published before (the ledger and the
/// lockdown journal): they are not somebody else's SPF or MX. A domain
/// inside a delegation needs none.
pub fn null_set(
	zone: &str,
	domain: &str,
	served: &ServedNames,
	existing: &[DnsRecord],
	ours: &[DnsRecord],
) -> NullSet {
	let cuts = Cuts::new(zone, existing);
	let mut set = NullSet::default();
	if cuts.above(domain).is_some() {
		return set;
	}
	let journal = Journal {
		domain: domain.to_string(),
		entries: ours
			.iter()
			.map(|record| JournalEntry {
				record: record.clone(),
				replaced: None,
			})
			.collect(),
	};
	let owns = |record: &DnsRecord| journal.owns(record);
	let exchanges = mx_owners(existing);
	let scope = names::Scope {
		served,
		exchanges: &exchanges,
		ours: &owns,
		cuts: &cuts,
	};
	for (name, (presence, records)) in names::candidates(domain, existing) {
		if !is_valid_name(&name) {
			continue;
		}
		let (spf_missing, mx_missing) = match names::decide(&name, presence, &records, &scope) {
			Some(Verdict::Add { spf, mx }) => (spf, mx),
			Some(Verdict::Done(_)) => (false, false),
			_ => continue,
		};
		let ours_spf = records
			.iter()
			.any(|r| r.kind == RecordKind::Txt && r.value == NULL_SPF && owns(r));
		let ours_mx = records
			.iter()
			.any(|r| r.kind == RecordKind::Mx && is_null_mx(&r.value) && owns(r));
		let (want_spf, want_mx) = (spf_missing || ours_spf, mx_missing || ours_mx);
		if want_spf {
			set.needed
				.push(DnsRecord::new(name.clone(), RecordKind::Txt, NULL_SPF, TTL));
		}
		if want_mx {
			set.needed
				.push(DnsRecord::new(name.clone(), RecordKind::Mx, NULL_MX, TTL));
		}
		if spf_missing || mx_missing {
			set.uncovered.push(name);
		}
	}
	let wildcard = format!("*.{domain}");
	match wildcard_decision(domain, existing, &journal, true, &cuts) {
		WildcardDecision::Added { .. } => {
			set.uncovered.push(wildcard.clone());
			set.needed
				.push(DnsRecord::new(wildcard, RecordKind::Txt, NULL_SPF, TTL));
		}
		WildcardDecision::AlreadyPresent { .. } => {
			set.needed
				.push(DnsRecord::new(wildcard, RecordKind::Txt, NULL_SPF, TTL));
		}
		WildcardDecision::Skipped { .. } => {}
	}
	set
}

/// Every domain of `hosted` that sits in `zone`, canonical, once.
pub fn hosted_in_zone(hosted: &[String], zone: &str) -> Vec<String> {
	let zone = canonical_name(zone);
	let found: BTreeSet<String> = hosted
		.iter()
		.map(|domain| canonical_name(domain))
		.filter(|domain| in_domain(domain, &zone))
		.collect();
	found.into_iter().collect()
}
