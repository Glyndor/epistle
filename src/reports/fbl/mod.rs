//! Read the spam complaints that mailbox providers send back as ARF reports
//! (RFC 5965) and suppress the complainant.
//!
//! The reports reach a mailbox the operator enrolled with the providers
//! (`[reports] fbl_mailbox`). The deliverer copies each one there as usual
//! and then hands the raw message to [`process`], which acts on a complaint
//! only when every check below holds, and otherwise changes nothing:
//!
//! 1. The envelope sender is one of the providers the operator enrolled
//!    (`fbl_senders`) and this server's own `Authentication-Results` says it
//!    proved it exactly: SPF passed for the exact domain of the envelope
//!    sender, or a DKIM signature passed whose `d=` is exactly that domain or
//!    the enrolled domain. The looser `sender_verified` flag, which accepts a
//!    sibling domain of the same organization and a login, is not used.
//! 2. The message is no larger than `MAX_ARF` (256 KiB) and is
//!    `multipart/report; report-type=feedback-report` with one
//!    machine-readable part, read with the bounds of the other report parsers.
//! 3. The `Feedback-Type` is `abuse` and the report names the complained-about
//!    recipient (`Original-Rcpt-To`), who is also an addressee (`To` or `Cc`)
//!    of the quoted message.
//! 4. The quoted headers are ours: the `Feedback-ID` this server writes
//!    (`epistle:<class>:<domain>`) for a hosted domain, a `Message-ID` of that
//!    domain, a `DKIM-Signature` by that domain with one of this server's
//!    selectors, and a single `From` address that is an account of the domain.
//!    A report quotes headers, usually without the body, so the signature
//!    cannot be verified; the provider that authenticated itself vouches for
//!    the quote, and these checks refuse one that is not shaped like our mail.
//! 5. The account is under its hourly cap (`fbl_max_per_hour`).
//!
//! The complaint is then added to the suppression list of that account, so
//! one account's complaint never costs another account its mail, and counted
//! per account and class. A `Feedback-ID` that a client wrote itself does not
//! match the form and is ignored.
//!
//! Nothing of the message is logged: not the recipient, the subject or the
//! body. The log line carries the account, the class, the domain and the
//! provider's domain.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::Reports;
use crate::evidence::MailClass;
use crate::metrics::Metrics;
use crate::queue::suppression::SuppressionList;
use crate::smtp::address::Address;
use crate::smtp::directory::Directory;
use crate::smtp::session::AcceptedMessage;

use super::bounds::{MAX_KEYWORD, MAX_TEXT, cap_text};
use super::mime;

mod auth;

/// What a message delivered to the report mailbox led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// Not from an enrolled provider, or not verified: nothing was read.
	Untrusted,
	/// Not a feedback report, or one that cannot be read.
	Unreadable,
	/// A report of a kind other than spam, or one without a recipient.
	NotActionable,
	/// A report about a message this server did not send, or that names a
	/// recipient the message did not have.
	NotOurs,
	/// The account is over its hourly cap: nothing was written.
	Limited,
	/// The complaint was counted; the recipient is on the account's list when
	/// suppression is on.
	Counted {
		/// The account that sent the message.
		account: String,
		/// The traffic class it was sent in.
		class: MailClass,
	},
	/// The recipient was already on the account's list: counted before.
	Duplicate,
}

/// The receiver, built from `[reports]`; absent when no mailbox is named.
#[derive(Debug, Clone)]
pub struct Fbl {
	mailbox: String,
	reports: Reports,
	hostname: String,
	selectors: Vec<String>,
	recent: Arc<Mutex<HashMap<String, VecDeque<u64>>>>,
}

impl Fbl {
	/// The receiver the configuration describes, or `None` when
	/// `fbl_mailbox` is not set.
	pub fn from_config(config: &crate::config::Config) -> Option<Self> {
		let selectors = config
			.dkim
			.as_ref()
			.map(|dkim| dkim.kept_selectors())
			.unwrap_or_default();
		Self::new(&config.reports, &config.hostname, selectors)
	}

	/// The receiver for `reports` on the server `hostname`, whose own DKIM
	/// selectors are `selectors`.
	pub fn new(reports: &Reports, hostname: &str, selectors: Vec<String>) -> Option<Self> {
		Some(Fbl {
			mailbox: reports.fbl_mailbox()?,
			reports: reports.clone(),
			hostname: hostname.to_ascii_lowercase(),
			selectors: selectors.iter().map(|s| s.to_ascii_lowercase()).collect(),
			recent: Arc::default(),
		})
	}

	/// Take one suppression of `account` from the hour's allowance.
	fn allow(&self, account: &str, now: u64) -> bool {
		let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
		let times = recent.entry(account.to_string()).or_default();
		while times
			.front()
			.is_some_and(|t| now.saturating_sub(*t) >= 3600)
		{
			times.pop_front();
		}
		if times.len() >= self.reports.max_per_hour() as usize {
			return false;
		}
		times.push_back(now);
		true
	}

	/// Whether `recipient` is the report mailbox.
	pub fn is_mailbox(&self, recipient: &str) -> bool {
		recipient.eq_ignore_ascii_case(&self.mailbox)
	}
}

/// Act on one message delivered to the report mailbox.
pub fn process(
	fbl: &Fbl,
	data_dir: &Path,
	directory: &Directory,
	message: &AcceptedMessage,
	metrics: Option<&Metrics>,
) -> Outcome {
	let proved = auth::stamped(&message.data, &fbl.hostname);
	let enrolled = fbl.reports.enrolled_entry(&message.reverse_path);
	if !enrolled.is_some_and(|entry| auth::proves(&proved, &message.reverse_path, &entry)) {
		tracing::info!("feedback report from a sender that is not an enrolled provider ignored");
		return Outcome::Untrusted;
	}
	let provider = message
		.reverse_path
		.rsplit_once('@')
		.map_or("", |(_, domain)| domain)
		.to_ascii_lowercase();
	let parts = match mime::find_arf_parts(&message.data) {
		Ok(parts) => parts,
		Err(mime::WalkError::NoReportPart) => {
			tracing::info!(%provider, "message to the feedback mailbox is not a feedback report");
			return Outcome::Unreadable;
		}
		Err(error) => {
			if let Some(metrics) = metrics {
				metrics.reports_dropped();
			}
			tracing::warn!(%provider, reason = %error, "feedback report dropped");
			return Outcome::Unreadable;
		}
	};
	let field = |name| mime::field(&parts.fields, name).map(|v| cap_text(&v, MAX_TEXT));
	if !field("feedback-type").is_some_and(|kind| kind.eq_ignore_ascii_case("abuse")) {
		tracing::info!(%provider, "feedback report is not a spam complaint");
		return Outcome::NotActionable;
	}
	let Some(recipient) = field("original-rcpt-to").and_then(|value| mailbox(&value)) else {
		tracing::info!(%provider, "feedback report names no recipient");
		return Outcome::NotActionable;
	};
	let Some((account, class, domain)) =
		sender_of(fbl, &parts.original_headers, directory, &recipient)
	else {
		tracing::info!(%provider, "feedback report is about a message this server did not send");
		return Outcome::NotOurs;
	};
	let class_name = class.to_string();
	if fbl.reports.suppresses() {
		if !fbl.allow(&account, now()) {
			tracing::warn!(%account, %provider, "complaints over the hourly cap are not recorded");
			return Outcome::Limited;
		}
		let reason = format!("spam complaint via {provider} ({class_name})");
		match SuppressionList::open(data_dir).and_then(|list| {
			list.try_suppress_for_because_once(&account, &recipient, &reason, now())
		}) {
			Ok(true) => {}
			Ok(false) => {
				tracing::info!(%account, class = %class_name, %domain, %provider, "complaint already recorded");
				return Outcome::Duplicate;
			}
			Err(error) => {
				tracing::warn!(%account, %error, "cannot record the complaint in the suppression list");
				return Outcome::Unreadable;
			}
		}
	}
	if let Some(metrics) = metrics {
		metrics.fbl_complaint(&account, &class_name);
	}
	tracing::info!(%account, class = %class_name, %domain, %provider, "spam complaint recorded");
	Outcome::Counted { account, class }
}

/// The account and class of the message the report quotes, when this server
/// sent it: a `Feedback-ID` of the form it writes, for a hosted domain, and
/// one `From` address of that domain that is an account of this server.
fn sender_of(
	fbl: &Fbl,
	original: &[u8],
	directory: &Directory,
	recipient: &str,
) -> Option<(String, MailClass, String)> {
	let feedback_id = mime::field(original, "feedback-id")?;
	let mut parts = cap_text(&feedback_id, MAX_KEYWORD * 4);
	parts.make_ascii_lowercase();
	let mut parts = parts.trim().split(':');
	let (Some("epistle"), Some(class), Some(domain), None) =
		(parts.next(), parts.next(), parts.next(), parts.next())
	else {
		return None;
	};
	let class = MailClass::parse(class)?;
	if !directory.hosts_domain(domain) {
		return None;
	}
	let crate::dmarc::author::Author::Addresses(addresses) = crate::dmarc::author::author(original)
	else {
		return None;
	};
	let [from] = addresses.as_slice() else {
		return None;
	};
	let address = Address::parse(from).ok()?;
	if !address.domain().eq_ignore_ascii_case(domain) {
		return None;
	}
	let account = directory.resolve_exact(&address)?;
	if !is_ours(fbl, original, domain, recipient) {
		return None;
	}
	Some((account, class, domain.to_string()))
}

/// The rest of what makes quoted headers ours: a `Message-ID` of the domain, a
/// `DKIM-Signature` by the domain with one of the server's selectors, and the
/// complainant among the addressees.
fn is_ours(fbl: &Fbl, original: &[u8], domain: &str, recipient: &str) -> bool {
	let Some(parsed) = mail_parser::MessageParser::new().parse_headers(original) else {
		return false;
	};
	let id_domain = parsed
		.message_id()
		.and_then(|id| id.rsplit_once('@'))
		.map(|(_, d)| d.trim_end_matches('>').to_ascii_lowercase());
	if id_domain.as_deref() != Some(domain) {
		return false;
	}
	let addressee = [parsed.to(), parsed.cc()]
		.into_iter()
		.flatten()
		.any(|list| {
			list.mailboxes().any(|one| {
				one.address()
					.is_some_and(|a| crate::util::address::normalize(a) == recipient)
			})
		});
	addressee && signed_by_us(fbl, original, domain)
}

/// Whether the headers carry a `DKIM-Signature` with `d=domain` and `s=` one
/// of this server's selectors.
fn signed_by_us(fbl: &Fbl, original: &[u8], domain: &str) -> bool {
	let text = String::from_utf8_lossy(original);
	let mut fields: Vec<String> = Vec::new();
	for line in text.lines() {
		match (line.starts_with([' ', '\t']), fields.last_mut()) {
			(true, Some(last)) => last.push_str(line.trim()),
			_ => fields.push(line.to_string()),
		}
	}
	fields.iter().any(|field| {
		let Some((name, value)) = field.split_once(':') else {
			return false;
		};
		if !name.trim().eq_ignore_ascii_case("dkim-signature") {
			return false;
		}
		let tag = |key: &str| {
			value.split(';').find_map(|part| {
				let (k, v) = part.split_once('=')?;
				(k.trim() == key).then(|| v.trim().to_ascii_lowercase())
			})
		};
		tag("d").as_deref() == Some(domain) && tag("s").is_some_and(|s| fbl.selectors.contains(&s))
	})
}

/// The plain mailbox in an `Original-Rcpt-To` value, lowercased.
fn mailbox(value: &str) -> Option<String> {
	let value = value.trim().trim_start_matches('<').trim_end_matches('>');
	crate::util::address::plain_mailbox(value)?;
	Some(crate::util::address::normalize(value))
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
