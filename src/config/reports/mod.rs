//! `[reports]`: the mailbox that receives spam complaints from the providers'
//! feedback loops, and who may be believed when a report says one arrived.
//!
//! Yahoo, Microsoft and Mail.ru send the complaints of their users back as ARF
//! reports (RFC 5965) to an address the operator enrols. Nothing here is on
//! until `fbl_mailbox` names that address: an absent section leaves the
//! mailbox an ordinary one.

use serde::Deserialize;

use super::ConfigError;

/// The `[reports]` configuration section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reports {
	/// The mailbox the feedback-loop reports are sent to, for example
	/// `fbl@example.org`. A hosted address the operator created and enrolled
	/// with the providers; the server never picks one. Absent turns the
	/// receiver off.
	#[serde(default)]
	pub fbl_mailbox: Option<String>,
	/// Add the complainant to the suppression list of the sending account.
	/// Absent follows `fbl_mailbox`: on when the mailbox is set.
	#[serde(default)]
	pub fbl_suppress: Option<bool>,
	/// The providers whose reports are believed: each entry is the envelope
	/// address a feedback loop sends from (`fbl@arf.example.net`) or a domain,
	/// which covers its subdomains. A report counts only when its envelope
	/// sender is one of these and this server verified that sender by SPF or by
	/// a DKIM signature aligned with it. Empty trusts nobody: reports are
	/// delivered to the mailbox and change nothing.
	#[serde(default)]
	pub fbl_senders: Vec<String>,
	/// The most complaints one sending account can have suppressed in an
	/// hour. A flood of reports that pass every check still cannot empty a
	/// customer's reach; the ones over the cap are logged and changed
	/// nothing. Absent is `DEFAULT_MAX_PER_HOUR` (100).
	#[serde(default)]
	pub fbl_max_per_hour: Option<u32>,
}

/// The default of `fbl_max_per_hour`.
pub const DEFAULT_MAX_PER_HOUR: u32 = 100;

/// Domains of public mailboxes: anybody can register an address there, so
/// the domain can never vouch for a feedback loop.
const PUBLIC_MAILBOX_DOMAINS: &[&str] = &[
	"gmail.com",
	"googlemail.com",
	"outlook.com",
	"hotmail.com",
	"live.com",
	"msn.com",
	"yahoo.com",
	"ymail.com",
	"aol.com",
	"icloud.com",
	"me.com",
	"mail.ru",
	"yandex.ru",
	"yandex.com",
	"proton.me",
	"protonmail.com",
	"gmx.com",
	"gmx.net",
	"gmx.de",
	"web.de",
	"qq.com",
	"163.com",
	"zoho.com",
	"fastmail.com",
];

impl Reports {
	/// The mailbox in the form the server compares: lowercase.
	pub fn fbl_mailbox(&self) -> Option<String> {
		self.fbl_mailbox.as_ref().map(|m| m.to_ascii_lowercase())
	}

	/// Whether a trusted complaint suppresses the complainant.
	pub fn suppresses(&self) -> bool {
		self.fbl_suppress.unwrap_or(self.fbl_mailbox.is_some())
	}

	/// Whether `sender`, an envelope address, is one of the enrolled
	/// providers: the same address, or an address of an enrolled domain or of
	/// one of its subdomains.
	pub fn trusts_sender(&self, sender: &str) -> bool {
		self.enrolled_entry(sender).is_some()
	}

	/// The `fbl_senders` entry that covers `sender`, lowercase.
	pub fn enrolled_entry(&self, sender: &str) -> Option<String> {
		let sender = sender.to_ascii_lowercase();
		let (_, domain) = sender.rsplit_once('@')?;
		self.fbl_senders
			.iter()
			.map(|entry| entry.to_ascii_lowercase())
			.find(|entry| {
				if entry.contains('@') {
					return *entry == sender;
				}
				domain == entry
					|| domain
						.strip_suffix(entry.as_str())
						.is_some_and(|rest| rest.ends_with('.'))
			})
	}

	/// The cap of suppressions per account and hour.
	pub fn max_per_hour(&self) -> u32 {
		self.fbl_max_per_hour.unwrap_or(DEFAULT_MAX_PER_HOUR)
	}
}

impl super::Config {
	/// The mailbox must be one plain address on a hosted domain, and each
	/// enrolled sender a plain address or a domain name. The setting that
	/// makes the server read mail from strangers is refused when it cannot
	/// work, not left to fail quietly.
	pub(in crate::config) fn validate_reports(&self) -> Result<(), ConfigError> {
		let reports = &self.reports;
		let invalid = |message: String| Err(ConfigError::Invalid(message));
		if let Some(mailbox) = &reports.fbl_mailbox {
			let Some((_, domain)) = crate::util::address::plain_mailbox(mailbox) else {
				return invalid(format!(
					"[reports] fbl_mailbox {mailbox:?} is not a plain mailbox (local@domain)"
				));
			};
			if !self
				.domains
				.iter()
				.any(|hosted| hosted.eq_ignore_ascii_case(domain))
			{
				return invalid(format!(
					"[reports] fbl_mailbox {mailbox:?} is not on a hosted domain"
				));
			}
		} else if reports.fbl_suppress == Some(true) || !reports.fbl_senders.is_empty() {
			return invalid(
				"[reports] fbl_suppress and fbl_senders need fbl_mailbox: name the mailbox the \
				 reports are sent to"
					.to_string(),
			);
		}
		if reports.fbl_max_per_hour == Some(0) {
			return invalid("[reports] fbl_max_per_hour must be at least 1".to_string());
		}
		for sender in &reports.fbl_senders {
			let domain = sender.rsplit_once('@').map_or(sender.as_str(), |(_, d)| d);
			let domain = domain.to_ascii_lowercase();
			if self.domains.iter().any(|hosted| {
				let hosted = hosted.to_ascii_lowercase();
				domain == hosted || domain.ends_with(&format!(".{hosted}"))
			}) {
				return invalid(format!(
					"[reports] fbl_senders entry {sender:?} is on a hosted domain: a provider \
					 is somebody else's server"
				));
			}
			if PUBLIC_MAILBOX_DOMAINS.contains(&domain.as_str()) {
				return invalid(format!(
					"[reports] fbl_senders entry {sender:?} is a public mailbox provider: anyone can \
					 hold an address there, so it cannot vouch for a report; enrol the address its \
					 feedback loop sends from, on a domain of its own"
				));
			}
			match sender.split_once('@') {
				Some(_) if crate::util::address::plain_mailbox(sender).is_none() => {
					return invalid(format!(
						"[reports] fbl_senders entry {sender:?} is not a plain mailbox"
					));
				}
				Some((_, domain)) => {
					super::validate_dns_name("[reports] fbl_senders domain", domain)?
				}
				None => super::validate_dns_name("[reports] fbl_senders domain", sender)?,
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
