//! The named groups of records automatic mode must not publish.
//!
//! The unit is a group and not a DNS type: `autoconfig` is a CNAME and
//! shares its type with the `mta-sts` name, which a deployment may want to
//! keep. The groups cover the records epistle publishes that depend on how
//! the operator runs the server; the core records (MX, SPF, DKIM, DMARC and
//! the addresses of the mail host) are in no group and can never be skipped.
//!
//! A group names records, not zones: the same group is skipped for every
//! domain the configuration hosts.

mod classify;
mod filter;

pub use classify::{group_of_check, group_of_record};
pub use filter::{split_checks, split_records};

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer};

use crate::dns::provider::DnsRecord;
use crate::dns::records::PublishRecord;

/// A named group of records the operator does not want published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipGroup {
	/// The SRV client locators and the names that reach the client setup
	/// documents (`autoconfig`, `autodiscover`).
	ClientLocators,
	/// The MTA-STS discovery record and the `mta-sts` name it needs.
	MtaSts,
	/// The TLS-RPT record, the address senders report to.
	TlsRpt,
	/// The DANE TLSA record of the mail host.
	Tlsa,
	/// The CAA record that locks issuance to the CA.
	Caa,
}

impl SkipGroup {
	/// Every group, in the order the configuration reference lists them.
	pub const ALL: [SkipGroup; 5] = [
		SkipGroup::ClientLocators,
		SkipGroup::MtaSts,
		SkipGroup::TlsRpt,
		SkipGroup::Tlsa,
		SkipGroup::Caa,
	];

	/// The name the configuration writes.
	pub const fn name(self) -> &'static str {
		match self {
			SkipGroup::ClientLocators => "client-locators",
			SkipGroup::MtaSts => "mta-sts",
			SkipGroup::TlsRpt => "tls-rpt",
			SkipGroup::Tlsa => "tlsa",
			SkipGroup::Caa => "caa",
		}
	}

	/// The group a name names, `None` when it names none.
	pub fn parse(name: &str) -> Option<SkipGroup> {
		SkipGroup::ALL
			.into_iter()
			.find(|group| group.name() == name)
	}

	/// The names of every group, for the error that names them.
	pub fn names() -> Vec<&'static str> {
		SkipGroup::ALL
			.into_iter()
			.map(|group| group.name())
			.collect()
	}
}

/// Read a group from the configuration. An unknown name is refused the way
/// an unknown key is: the error names the groups that exist.
impl<'de> Deserialize<'de> for SkipGroup {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct GroupVisitor;

		impl serde::de::Visitor<'_> for GroupVisitor {
			type Value = SkipGroup;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(
					formatter,
					"one of the groups: {}",
					SkipGroup::names().join(", ")
				)
			}

			fn visit_str<E>(self, value: &str) -> Result<SkipGroup, E>
			where
				E: serde::de::Error,
			{
				SkipGroup::parse(value).ok_or_else(|| {
					E::custom(format!(
						"unknown [dns_publish] skip group {value:?}; the groups are: {}",
						SkipGroup::names().join(", ")
					))
				})
			}
		}

		deserializer.deserialize_str(GroupVisitor)
	}
}

/// The groups the configuration skips.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkipSet {
	groups: BTreeSet<SkipGroup>,
}

impl SkipSet {
	/// The set of the groups in `groups`.
	pub fn new(groups: impl IntoIterator<Item = SkipGroup>) -> Self {
		SkipSet {
			groups: groups.into_iter().collect(),
		}
	}

	/// Whether the set skips nothing.
	pub fn is_empty(&self) -> bool {
		self.groups.is_empty()
	}

	/// Whether the set skips `group`.
	pub fn contains(&self, group: SkipGroup) -> bool {
		self.groups.contains(&group)
	}

	/// The groups the set skips, in the order of [`SkipGroup::ALL`].
	pub fn groups(&self) -> Vec<SkipGroup> {
		SkipGroup::ALL
			.into_iter()
			.filter(|group| self.groups.contains(group))
			.collect()
	}

	/// The group `record` belongs to, when the set skips it.
	pub fn group_of(&self, record: &DnsRecord) -> Option<SkipGroup> {
		group_of_record(record).filter(|group| self.groups.contains(group))
	}

	/// Why a ledger record of the set is retired: epistle published it and
	/// the configuration skips the group it belongs to, or no longer needs
	/// the record.
	pub fn retirement_reason(&self, record: &DnsRecord) -> String {
		let name = crate::dns::names::canonical_name(&record.name);
		let kind = record.kind.as_str();
		match self.group_of(record) {
			Some(group) => format!(
				"{name} {kind} was published by epistle and the configuration skips the {} group",
				group.name()
			),
			None => format!(
				"{name} {kind} was published by epistle and the configuration no longer needs it"
			),
		}
	}
}

/// A group the configuration skips, and the records it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedGroup {
	/// The group.
	pub group: SkipGroup,
	/// The records the wanted set held for it.
	pub records: Vec<PublishRecord>,
}
