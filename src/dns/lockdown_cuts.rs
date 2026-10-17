//! Delegations in the zone the lockdown reads. An NS rrset at a name below
//! the zone apex hands that name, and every name under it, to other
//! nameservers (a zone cut): whatever the zone holds there is occluded,
//! some providers refuse to store it, and whatever the lockdown wrote
//! would never be served. The plan leaves those names alone and says so.
//!
//! The NS rrset at the apex is not a cut: it names the servers of this very
//! zone.

use std::collections::HashSet;

use super::names::{canonical_name, in_domain};
use crate::dns::provider::{DnsRecord, RecordKind};

/// The longest DNS name, without the root dot (RFC 1035 section 2.3.4).
pub const MAX_NAME_LEN: usize = 253;

/// The longest label of a DNS name (RFC 1035 section 2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Whether `name`, in [`canonical_name`] form, is a name the lockdown may
/// plan a record at: within the length caps, no empty label, and every label
/// made of ASCII letters, digits, hyphens and underscores, except that the
/// first label may be `*`. A provider hands the lockdown whatever the zone
/// holds, and a record is written back under the name that was read, so a
/// name with an escape sequence, a NUL or a space is reported and left
/// alone, never written to.
pub fn is_valid_name(name: &str) -> bool {
	if name.is_empty() || name.len() > MAX_NAME_LEN {
		return false;
	}
	name.split('.').enumerate().all(|(index, label)| {
		!label.is_empty()
			&& label.len() <= MAX_LABEL_LEN
			&& ((index == 0 && label == "*")
				|| label
					.bytes()
					.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
	})
}

/// `name` cut to at most [`MAX_NAME_LEN`] bytes (on a character boundary),
/// with an ellipsis when it was cut, for a message about a name that is not
/// valid.
pub fn shortened(name: &str) -> String {
	if name.len() <= MAX_NAME_LEN {
		return name.to_string();
	}
	let mut end = MAX_NAME_LEN;
	while !name.is_char_boundary(end) {
		end -= 1;
	}
	format!("{}...", &name[..end])
}

/// The zone cuts of one zone.
#[derive(Debug)]
pub struct Cuts {
	zone: String,
	names: HashSet<String>,
}

impl Cuts {
	/// The cuts `existing` holds: every canonical name under the canonical
	/// `zone`, apex excluded, that carries an NS record.
	pub fn new(zone: &str, existing: &[DnsRecord]) -> Self {
		let names = existing
			.iter()
			.filter(|r| r.kind == RecordKind::Ns)
			.map(|r| canonical_name(&r.name))
			.filter(|name| name != zone && in_domain(name, zone) && is_valid_name(name))
			// An NS at a wildcard does not delegate anything (RFC 4592): it is
			// no zone cut, and no name is left alone because of it.
			.filter(|name| !name.starts_with("*."))
			.collect();
		Cuts {
			zone: zone.to_string(),
			names,
		}
	}

	/// The cut that covers canonical `name`: the highest name between the
	/// apex (excluded) and `name` (included) that carries NS records. A
	/// nameserver owns everything under the highest cut above it, so that
	/// is the one the operator is told about. Cost: one hash lookup per
	/// label of `name`, never more than [`MAX_NAME_LEN`] bytes of it.
	pub fn above(&self, name: &str) -> Option<&str> {
		if self.names.is_empty() || name.len() > MAX_NAME_LEN {
			return None;
		}
		let below = name.strip_suffix(self.zone.as_str())?.strip_suffix('.')?;
		let starts = below
			.bytes()
			.enumerate()
			.rev()
			.filter(|(_, byte)| *byte == b'.')
			.map(|(at, _)| at + 1)
			.chain(std::iter::once(0));
		starts
			.filter_map(|start| self.names.get(&name[start..]))
			.next()
			.map(String::as_str)
	}

	/// The cuts that matter for `domain`: the ones at or under it, and the
	/// ones above it (a domain inside a delegation), sorted.
	pub fn relevant_to(&self, domain: &str) -> Vec<&str> {
		let mut cuts: Vec<&str> = self
			.names
			.iter()
			.filter(|cut| in_domain(cut, domain) || in_domain(domain, cut))
			.map(String::as_str)
			.collect();
		cuts.sort_unstable();
		cuts
	}
}
