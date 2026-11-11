//! The role of a hosted domain: which groups of records its DNS carries.
//!
//! A `full` domain is the default and carries everything the deployment
//! publishes. A `send-only` domain only sends mail: it needs SPF, DKIM,
//! DMARC and the MX, and none of what a mailbox user or a sender reaches the
//! domain through (MTA-STS, TLS-RPT, the SRV locators, `autoconfig` and
//! `autodiscover`). The role is one more reason a group is skipped, read by
//! the same filter as `[dns_publish] skip`, so `dns-records`, `domain add`,
//! `verify-dns`, `status` and the publisher all agree on it.

use std::collections::BTreeSet;

use super::SkipGroup;
use crate::dns::names::canonical_name;

/// What a hosted domain is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DomainRole {
	/// Mail is received, sent and set up by clients: every record.
	#[default]
	Full,
	/// Mail is only sent: SPF, DKIM, DMARC and MX.
	SendOnly,
}

impl DomainRole {
	/// The name the command line and the output use.
	pub const fn name(self) -> &'static str {
		match self {
			DomainRole::Full => "full",
			DomainRole::SendOnly => "send-only",
		}
	}

	/// The groups a domain of this role does not carry.
	pub const fn omits(self) -> &'static [SkipGroup] {
		match self {
			DomainRole::Full => &[],
			DomainRole::SendOnly => &[
				SkipGroup::ClientLocators,
				SkipGroup::MtaSts,
				SkipGroup::TlsRpt,
			],
		}
	}
}

/// The role of each hosted domain, read from a record or a checked name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roles {
	/// Every hosted domain, lowercase.
	hosted: Vec<String>,
	/// The hosted domains that are `send-only`, lowercase.
	send_only: BTreeSet<String>,
}

impl Roles {
	/// The roles of `hosted`, of which `send_only` are send-only.
	pub fn new(hosted: &[String], send_only: &[String]) -> Self {
		Roles {
			hosted: hosted.iter().map(|d| d.to_ascii_lowercase()).collect(),
			send_only: send_only.iter().map(|d| d.to_ascii_lowercase()).collect(),
		}
	}

	/// The role of the hosted domain `name` is in: the longest hosted
	/// domain that is `name` or a suffix of it, so a record of
	/// `sub.example.org` is not read as one of `example.org`. A name in no
	/// hosted domain (the mail host's own) is `full`.
	pub fn of_name(&self, name: &str) -> DomainRole {
		let name = canonical_name(name);
		let owner = self
			.hosted
			.iter()
			.filter(|domain| {
				name == **domain
					|| name
						.strip_suffix(domain.as_str())
						.is_some_and(|head| head.ends_with('.'))
			})
			.max_by_key(|domain| domain.len());
		match owner {
			Some(domain) if self.send_only.contains(domain) => DomainRole::SendOnly,
			_ => DomainRole::Full,
		}
	}
}
