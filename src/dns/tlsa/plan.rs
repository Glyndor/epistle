//! Who wrote the TLSA records at the name, and what that allows.
//!
//! A TLSA set at `_25._tcp.<host>` may hold records epistle did not write:
//! two nodes with their own certificates, or a rotation overlap of somebody
//! else. A value is epistle's own when it is one this instance published
//! before (the state keeps them) or the association of a certificate it
//! served before the change. Every other value is foreign, and a refresh
//! never removes it.

use crate::dns::provider::DnsRecord;

/// A TLSA value compared the way DNS compares it: whitespace-insensitive
/// and case-insensitive on the hex.
pub(super) fn normal(value: &str) -> String {
	value
		.split_whitespace()
		.collect::<Vec<_>>()
		.join(" ")
		.to_ascii_lowercase()
}

/// What the set at the name asks of the refresh.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
	/// The new value is in the set already; nothing is written.
	Present {
		/// The newest known old value still there, kept as the overlap.
		overlap: Option<DnsRecord>,
	},
	/// The new value has to be written.
	Write {
		/// The records of somebody else, which must survive.
		foreign: Vec<DnsRecord>,
		/// The newest known old value in the set: it stays next to the new
		/// one until the next rotation, so a sender that cached the old
		/// association still validates.
		overlap: Option<DnsRecord>,
	},
}

/// Decide for `set` (the TLSA records at the name), the `value` to publish
/// and the `known` values, newest first, that this instance wrote.
pub(super) fn decide(set: &[DnsRecord], value: &str, known: &[String]) -> Decision {
	let wanted = normal(value);
	let known: Vec<String> = known.iter().map(|value| normal(value)).collect();
	let overlap = known
		.iter()
		.filter(|old| **old != wanted)
		.find_map(|old| set.iter().find(|record| normal(&record.value) == *old))
		.cloned();
	if set.iter().any(|record| normal(&record.value) == wanted) {
		return Decision::Present { overlap };
	}
	let foreign = set
		.iter()
		.filter(|record| !known.contains(&normal(&record.value)))
		.cloned()
		.collect();
	Decision::Write { foreign, overlap }
}
