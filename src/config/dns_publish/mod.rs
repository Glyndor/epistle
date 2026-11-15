//! `[dns_publish]`: how automatic mode keeps the DNS records true.
//!
//! With a `[dns]` provider that can write, the server compares the zones with
//! the configuration every `interval_secs` and applies the difference through
//! the code `epistle dns publish` runs. Without one (manual mode) none of
//! this runs and the section is only read by the command.
//!
//! The `senders` list names what may send mail besides the hosted domains;
//! `epistle dns lockdown` leaves those names alone and protects the rest.
//!
//! The `skip` list names the groups of records automatic mode must not
//! publish: the records of a group are never written, and a record epistle
//! published earlier is retired through the ledger like a record the
//! configuration no longer needs.
//!
//! The `extra_txt` list names the TXT records the operator supplies: a
//! domain verification token (the one Google Postmaster Tools asks for) or
//! any other TXT epistle does not derive from the configuration. They are
//! published with the records epistle derives and kept published while they
//! are in the list.

use std::collections::HashSet;

use serde::Deserialize;

use super::ConfigError;
use crate::config::validate_dns_name;
use crate::dns::skip::{SkipGroup, SkipSet};

/// Six hours between two runs of the reconcile loop.
pub const DEFAULT_INTERVAL_SECS: u64 = 21_600;

/// The shortest interval accepted: ten minutes. Shorter would spend the
/// provider's API quota on a zone that rarely changes.
pub const MIN_INTERVAL_SECS: u64 = 600;

/// The longest interval accepted: one week.
pub const MAX_INTERVAL_SECS: u64 = 604_800;

/// The `[dns_publish]` section.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsPublish {
	/// Seconds between two runs of the server's reconcile loop in automatic
	/// mode; `0` turns the loop off. Between 600 and 604800 otherwise.
	#[serde(default = "default_interval")]
	pub interval_secs: u64,
	/// The named groups automatic mode must not publish. Empty by default:
	/// every record the configuration needs is published.
	#[serde(default)]
	pub skip: Vec<SkipGroup>,
	/// Whether the DANE TLSA record may be published.
	///
	/// Off by default: a TLSA record is only safe in a zone that is
	/// signed with DNSSEC. A validating resolver ignores the record in
	/// an unsigned zone, and a resolver that does not validate applies
	/// it — so a record naming a certificate the server no longer
	/// presents makes the senders that honour DANE refuse the mail
	/// (RFC 7672). The operator turns it on for a zone that is signed.
	#[serde(default)]
	pub dane: bool,
	/// The names under a hosted domain that send mail. Hosted domains
	/// themselves count and need no entry; every other name under them is
	/// not a sender, and `epistle dns lockdown` gives it a null SPF and a
	/// null MX unless it has records of its own. Empty by default.
	#[serde(default)]
	pub senders: Vec<String>,
	/// Keep the null SPF and null MX `dns lockdown` publishes true in
	/// automatic mode: a name added to the zone later is covered on the
	/// next run, and one that becomes a sender or gets records of its own
	/// loses them. Off by default.
	#[serde(default)]
	pub null_records: bool,
	/// The TXT records the operator supplies. Empty by default: epistle
	/// publishes only the records it derives from the configuration.
	#[serde(default)]
	pub extra_txt: Vec<ExtraTxt>,
}

/// A TXT record the operator supplies: a domain verification token (the one
/// Google Postmaster Tools asks for) or any other TXT epistle does not
/// derive from the configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtraTxt {
	/// The name the record is published at.
	pub name: String,
	/// The value of the record.
	pub value: String,
}

impl Default for DnsPublish {
	fn default() -> Self {
		DnsPublish {
			interval_secs: DEFAULT_INTERVAL_SECS,
			skip: Vec::new(),
			dane: false,
			senders: Vec::new(),
			null_records: false,
			extra_txt: Vec::new(),
		}
	}
}

fn default_interval() -> u64 {
	DEFAULT_INTERVAL_SECS
}

impl DnsPublish {
	/// The groups to skip, as a set the record filter reads.
	pub fn skip_set(&self) -> SkipSet {
		SkipSet::new(self.skip.iter().copied())
	}

	/// Refuse an interval outside the accepted range, and a supplied TXT
	/// record epistle cannot publish.
	pub(crate) fn validate(&self, domains: &[String]) -> Result<(), ConfigError> {
		let secs = self.interval_secs;
		if secs != 0 && !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs) {
			return Err(ConfigError::Invalid(format!(
				"[dns_publish] interval_secs = {secs}: use 0 to turn the reconcile loop off, or a value from {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS}"
			)));
		}
		self.validate_extra_txt(domains)
	}

	/// Every supplied TXT record names a DNS name at or under a hosted
	/// domain and carries a value: a record epistle cannot place in a zone
	/// it holds is one the operator would never see published.
	fn validate_extra_txt(&self, domains: &[String]) -> Result<(), ConfigError> {
		let mut seen: HashSet<(String, String)> = HashSet::new();
		for extra in &self.extra_txt {
			validate_dns_name("[dns_publish] extra_txt name", &extra.name)?;
			if extra.value.trim().is_empty() {
				return Err(ConfigError::Invalid(
					"[dns_publish] extra_txt value must not be empty".into(),
				));
			}
			let name = extra.name.trim().to_ascii_lowercase();
			let hosted = domains.iter().any(|domain| {
				let domain = domain.trim().to_ascii_lowercase();
				name == domain || name.ends_with(&format!(".{domain}"))
			});
			if !hosted {
				return Err(ConfigError::Invalid(format!(
					"[dns_publish] extra_txt name \"{}\" is not a hosted domain or a name under one",
					extra.name
				)));
			}
			if !seen.insert((name, extra.value.clone())) {
				return Err(ConfigError::Invalid(format!(
					"duplicate [dns_publish] extra_txt entry \"{}\"",
					extra.name
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
