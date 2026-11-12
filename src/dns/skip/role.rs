//! The role of a hosted domain: which groups of records its DNS carries.
//!
//! A `full` domain is the default and carries everything the deployment
//! publishes. A `send-only` domain only sends mail: it needs SPF, DKIM,
//! DMARC and the MX, and none of what a mailbox user or a sender reaches the
//! domain through (MTA-STS, TLS-RPT, the SRV locators, `autoconfig` and
//! `autodiscover`). A `receive-only` domain sends nothing: its SPF is the
//! null SPF, it has no DKIM key in DNS and its DMARC policy is `reject`.
//! A `disabled` domain (`disabled_domains`) neither sends nor receives: the
//! same, with a null MX and none of the receiving groups. The role is one
//! more reason a group is skipped, read by the same filter as
//! `[dns_publish] skip`, so `dns-records`, `domain add`, `verify-dns`,
//! `status` and the publisher all agree on it.

use std::collections::BTreeSet;

use super::SkipGroup;
use crate::dns::lockdown::{NULL_MX, NULL_SPF};
use crate::dns::names::canonical_name;

/// What a hosted domain is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DomainRole {
	/// Mail is received, sent and set up by clients: every record.
	#[default]
	Full,
	/// Mail is only sent: SPF, DKIM, DMARC and MX.
	SendOnly,
	/// Mail is only received: nothing is sent as the domain.
	ReceiveOnly,
	/// The domain is switched off: mail is neither sent nor received.
	Disabled,
}

impl DomainRole {
	/// The name the command line and the output use.
	pub const fn name(self) -> &'static str {
		match self {
			DomainRole::Full => "full",
			DomainRole::SendOnly => "send-only",
			DomainRole::ReceiveOnly => "receive-only",
			DomainRole::Disabled => "disabled",
		}
	}

	/// Whether mail is sent as the domain: it needs a DKIM key in DNS and an
	/// SPF that names the mail host.
	pub const fn sends(self) -> bool {
		matches!(self, DomainRole::Full | DomainRole::SendOnly)
	}

	/// Whether the domain has mailboxes that read mail: the MX names the mail
	/// host and aggregate reports have somebody to read them.
	pub const fn receives(self) -> bool {
		matches!(self, DomainRole::Full | DomainRole::ReceiveOnly)
	}

	/// The SPF record of the domain: the mail host's MX hosts when it sends,
	/// the null SPF (RFC 7208) otherwise.
	pub const fn spf(self) -> &'static str {
		if self.sends() {
			"v=spf1 mx -all"
		} else {
			NULL_SPF
		}
	}

	/// The MX record of the domain: the mail host at the standard priority,
	/// or the null MX (RFC 7505) when the domain accepts no mail at all.
	pub fn mx(self, hostname: &str) -> String {
		match self {
			DomainRole::Disabled => NULL_MX.to_string(),
			_ => format!("10 {hostname}"),
		}
	}

	/// The DMARC policy: a domain that sends nothing has no legitimate
	/// message to quarantine, so a message that claims it is rejected.
	pub const fn dmarc_policy(self) -> &'static str {
		if self.sends() { "quarantine" } else { "reject" }
	}

	/// The groups a domain of this role does not carry.
	pub const fn omits(self) -> &'static [SkipGroup] {
		match self {
			DomainRole::Full => &[],
			DomainRole::SendOnly | DomainRole::Disabled => &[
				SkipGroup::ClientLocators,
				SkipGroup::MtaSts,
				SkipGroup::TlsRpt,
			],
			DomainRole::ReceiveOnly => &[],
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
	/// The hosted domains that are `receive-only`, lowercase.
	receive_only: BTreeSet<String>,
	/// The hosted domains that are switched off, lowercase.
	disabled: BTreeSet<String>,
}

impl Roles {
	/// The roles of `hosted`, of which `send_only` are send-only.
	pub fn new(hosted: &[String], send_only: &[String]) -> Self {
		Roles {
			hosted: hosted.iter().map(|d| d.to_ascii_lowercase()).collect(),
			send_only: send_only.iter().map(|d| d.to_ascii_lowercase()).collect(),
			..Roles::default()
		}
	}

	/// The same roles, also with the `receive-only` domains and the ones
	/// that are switched off. A switched-off domain is `disabled` whatever
	/// else lists it.
	pub fn with_others(mut self, receive_only: &[String], disabled: &[String]) -> Self {
		self.receive_only = receive_only
			.iter()
			.map(|d| d.to_ascii_lowercase())
			.collect();
		self.disabled = disabled.iter().map(|d| d.to_ascii_lowercase()).collect();
		self
	}

	/// The role of the hosted domain `domain` itself.
	fn role_of(&self, domain: &str) -> DomainRole {
		if self.disabled.contains(domain) {
			DomainRole::Disabled
		} else if self.send_only.contains(domain) {
			DomainRole::SendOnly
		} else if self.receive_only.contains(domain) {
			DomainRole::ReceiveOnly
		} else {
			DomainRole::Full
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
		owner.map_or(DomainRole::Full, |domain| self.role_of(domain))
	}
}
