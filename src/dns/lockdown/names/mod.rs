//! Which names under a domain get the null SPF and the null MX, and why
//! the others are left alone.
//!
//! One decision for every name, whatever the depth: a name that is not
//! declared as sending (served by epistle, or listed in `[dns_publish]
//! senders`) and has no record of its own for the purpose gets `v=spf1 -all`
//! and `MX 0 .`. A name counts when it owns any record, or when it is the
//! parent of a name that does (an empty non-terminal: a wildcard never
//! answers for it, because the name exists), or when it is the apex of the
//! domain. Names that do not exist at all are the wildcard's.

use std::collections::{BTreeMap, BTreeSet};

use crate::dns::names::{MAX_NAME_LEN, ServedNames, canonical_name, in_domain, is_valid_name};
use crate::dns::provider::{DnsRecord, RecordKind, txt_purpose};
use crate::dns::rrset::Cuts;

/// What one name gets.
pub(super) enum Verdict {
	/// The name is left alone, for this reason.
	Skip(String),
	/// The name gets the null SPF, the null MX, or both.
	Add { spf: bool, mx: bool },
}

/// How a name came to be a candidate, for the reason printed in the plan.
#[derive(Clone, Copy)]
pub(super) enum Presence {
	/// It owns an A, AAAA or CNAME record.
	Address,
	/// It owns other records but no address.
	Records,
	/// It owns nothing: it is the parent of a name that does, or the apex.
	Empty,
}

impl Presence {
	/// The words the plan says about the name.
	pub(super) fn describe(self) -> &'static str {
		match self {
			Presence::Address => "has an address record",
			Presence::Records => "has records",
			Presence::Empty => "has no records of its own",
		}
	}
}

/// The candidates: every name at or under `domain` the zone knows, with
/// the records it owns (none for a parent name or the apex without
/// records), sorted. Wildcards are not candidates (the wildcard has its own
/// decision) but a name a wildcard sits under is one. One pass over the
/// zone plus the labels of each name: the cost does not depend on how many
/// names there are.
pub(super) fn candidates<'a>(
	domain: &str,
	existing: &'a [DnsRecord],
) -> BTreeMap<String, (Presence, Vec<&'a DnsRecord>)> {
	let mut owned: BTreeMap<String, Vec<&DnsRecord>> = BTreeMap::new();
	let mut parents: BTreeSet<String> = BTreeSet::new();
	parents.insert(domain.to_string());
	for record in existing {
		let name = canonical_name(&record.name);
		if !in_domain(&name, domain) {
			continue;
		}
		let plain = name.strip_prefix("*.").unwrap_or(&name);
		if is_valid_name(plain) && plain.len() <= MAX_NAME_LEN {
			let mut above = plain;
			while above != domain {
				parents.insert(above.to_string());
				match above.split_once('.') {
					Some((_, rest)) => above = rest,
					None => break,
				}
			}
		}
		if !name.starts_with("*.") {
			owned.entry(name).or_default().push(record);
		}
	}
	for parent in parents {
		owned.entry(parent).or_default();
	}
	owned
		.into_iter()
		.map(|(name, records)| {
			let presence = if records.is_empty() {
				Presence::Empty
			} else if records.iter().any(|r| is_address(r)) {
				Presence::Address
			} else {
				Presence::Records
			};
			(name, (presence, records))
		})
		.collect()
}

fn is_address(record: &DnsRecord) -> bool {
	matches!(
		record.kind,
		RecordKind::A | RecordKind::Aaaa | RecordKind::Cname
	)
}

/// What `decide` reads besides the name and its records.
pub(super) struct Scope<'a> {
	/// The names epistle serves and the names declared as sending.
	pub served: &'a ServedNames,
	/// Every MX target in the zone, with the first name pointing at it.
	pub exchanges: &'a BTreeMap<String, String>,
	/// Whether a record is one epistle published before (the lockdown's
	/// journal, and later the ledger): its own null records are not
	/// somebody else's SPF or MX.
	pub ours: &'a dyn Fn(&DnsRecord) -> bool,
	/// The zone cuts: nothing is decided under one.
	pub cuts: &'a Cuts,
}

/// Decide what one candidate gets, or `None` when it sits inside a
/// delegation (reported once, by the cut, not here). The order matters:
/// a name epistle serves is reported as such even when it is a CNAME.
pub(super) fn decide(
	name: &str,
	presence: Presence,
	records: &[&DnsRecord],
	scope: &Scope<'_>,
) -> Option<Verdict> {
	if scope.cuts.above(name).is_some() {
		return None;
	}
	if let Some(role) = scope.served.role(name) {
		// A served name that holds no address record (`_dmarc`, the apex of
		// a hosted domain with only TXT records) is not a host that could be
		// mistaken for one that sends: it is not reported.
		if !matches!(presence, Presence::Address) {
			return None;
		}
		return Some(Verdict::Skip(format!(
			"epistle serves {name} ({role}); left as is"
		)));
	}
	if scope.served.sends(name) {
		return Some(Verdict::Skip(format!(
			"{name} is listed in [dns_publish] senders: it sends mail, so it keeps the SPF it has or needs; left as is"
		)));
	}
	if name.split('.').any(|label| label.starts_with('_')) {
		if !matches!(presence, Presence::Address) {
			return None;
		}
		return Some(Verdict::Skip(format!(
			"{name} is a service name (a label starts with an underscore), not a host that sends mail; left as is"
		)));
	}
	if records.iter().any(|r| r.kind == RecordKind::Cname) {
		return Some(Verdict::Skip(format!(
			"{name} is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is"
		)));
	}
	let own_spf = records.iter().any(|r| is_spf(r) && !(scope.ours)(r));
	let own_mx = records
		.iter()
		.any(|r| r.kind == RecordKind::Mx && !(scope.ours)(r));
	match (own_spf, own_mx) {
		(true, true) => {
			return Some(Verdict::Skip(format!(
				"{name} has its own SPF and MX records; left as is"
			)));
		}
		(true, false) => {
			return Some(Verdict::Skip(format!(
				"{name} has its own SPF record; left as is"
			)));
		}
		(false, true) => {
			return Some(Verdict::Skip(format!(
				"{name} has its own MX record; left as is"
			)));
		}
		(false, false) => {}
	}
	if let Some(owner) = scope.exchanges.get(name) {
		return Some(Verdict::Skip(format!(
			"{name} is an MX target of {owner}, so it is a mail server and may send as itself; left as is"
		)));
	}
	let spf = !records.iter().any(|r| is_spf(r));
	let mx = !records.iter().any(|r| r.kind == RecordKind::Mx);
	if !spf && !mx {
		return Some(Verdict::Skip(format!(
			"{name} already has the null SPF and null MX this command published"
		)));
	}
	Some(Verdict::Add { spf, mx })
}

fn is_spf(record: &DnsRecord) -> bool {
	record.kind == RecordKind::Txt && txt_purpose(&record.value) == Some("v=spf1")
}

#[cfg(test)]
mod tests;
