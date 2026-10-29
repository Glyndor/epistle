//! Abuse Reporting Format (ARF) feedback reports, RFC 5965.
//!
//! When a message is reported as abuse, we emit a
//! `multipart/report; report-type=feedback-report` message: a human-readable
//! part, a machine-readable `message/feedback-report` part, and the reported
//! message itself.

use crate::clock;
use crate::smtp::session::AcceptedMessage;
use crate::util::header::sanitize_header_value;

/// The kind of abuse being reported (RFC 5965 §7.3 Feedback-Type registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackType {
	/// Unsolicited bulk/abusive mail.
	Abuse,
	/// Reporter is not sure / generic.
	Other,
}

impl FeedbackType {
	fn as_str(self) -> &'static str {
		match self {
			FeedbackType::Abuse => "abuse",
			FeedbackType::Other => "other",
		}
	}
}

/// Details of a reported message.
pub struct Report<'a> {
	/// Where the feedback report is sent (the abuse contact).
	pub report_to: &'a str,
	/// What is being reported.
	pub feedback_type: FeedbackType,
	/// The envelope sender of the offending message.
	pub original_mail_from: &'a str,
	/// The connecting client IP, if known.
	pub source_ip: Option<&'a str>,
	/// The reported message, raw.
	pub reported_message: &'a [u8],
}

/// Largest reported message embedded in a report.
const MAX_EMBEDDED: usize = 50_000;

/// Build an ARF feedback report message.
pub fn build(hostname: &str, report: &Report, now: std::time::SystemTime) -> AcceptedMessage {
	let date = clock::rfc5322(now);
	let boundary = format!(
		"=_arf_{}",
		now.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	);
	// `original_mail_from` and `source_ip` come from an inbound ARF
	// complaint (the feedback loop from another provider's mailbox): the
	// message is not authenticated, and a CRLF in either value would
	// inject forged headers into our feedback report. Sanitize before the
	// values reach any `format!`, matching what
	// `src/cli/report_abuse.rs::build_report` does for the operator-driven
	// path. `reported_domain` is derived from the sanitised
	// `original_mail_from` so it cannot carry an injection either.
	let original_mail_from = sanitize_header_value(report.original_mail_from);
	let reported_domain = original_mail_from
		.rsplit_once('@')
		.map(|(_, domain)| sanitize_header_value(domain))
		.unwrap_or_default();
	let source_ip = report.source_ip.map(sanitize_header_value);

	let mut feedback = format!(
		"Feedback-Type: {}\r\n\
 User-Agent: {hostname}\r\n\
 Version: 1\r\n\
 Original-Mail-From: {}\r\n\
 Arrival-Date: {date}\r\n\
 Reported-Domain: {reported_domain}\r\n",
		report.feedback_type.as_str(),
		original_mail_from,
	);
	if let Some(ip) = source_ip {
		feedback.push_str(&format!("Source-IP: {ip}\r\n"));
	}

	let embedded = embed(report.reported_message);

	let body = format!(
		"From: abuse-reporter@{hostname}\r\n\
To: <{report_to}>\r\n\
Subject: Email abuse report\r\n\
Date: {date}\r\n\
Auto-Submitted: auto-generated\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=feedback-report;\r\n\
\tboundary=\"{boundary}\"\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
This is an abuse report for a message received from {reported_domain}.\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
{feedback}\
\r\n\
--{boundary}\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
{embedded}\r\n\
--{boundary}--\r\n",
		report_to = report.report_to,
	);

	AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![report.report_to.to_string()],
		data: crate::util::header_block::frame_generated(body.into_bytes()),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// The reported message, truncated to a sane size for embedding.
fn embed(message: &[u8]) -> String {
	let cut = &message[..message.len().min(MAX_EMBEDDED)];
	// Cut on a whole line unless the message fits.
	let end = match cut.len() == message.len() {
		true => cut.len(),
		false => cut
			.iter()
			.rposition(|byte| *byte == b'\n')
			.map_or(0, |at| at + 1),
	};
	String::from_utf8_lossy(&message[..end]).to_string()
}

/// The machine-readable fields of an inbound ARF feedback report.
///
/// Produced by [`parse`] from the `message/feedback-report` part of an
/// incoming complaint (e.g. a mailbox provider's feedback loop), so the
/// queue can act on it — suppress the complained-about recipient, adjust
/// reputation, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReport {
	/// `Feedback-Type` (e.g. `abuse`, `fraud`, `other`) — always present.
	pub feedback_type: String,
	/// `Original-Mail-From`: the envelope sender of the offending message.
	pub original_mail_from: Option<String>,
	/// `Source-IP`: the connecting client IP of the offending message.
	pub source_ip: Option<String>,
	/// `Reported-Domain`: the domain the complaint is about.
	pub reported_domain: Option<String>,
	/// `Arrival-Date`: when the offending message was received.
	pub arrival_date: Option<String>,
}

/// Largest report we will scan when parsing — a DoS bound on hostile input.
const MAX_PARSE: usize = 1_000_000;

/// Parse an inbound `multipart/report; report-type=feedback-report` message,
/// extracting the fields of its `message/feedback-report` part.
///
/// Returns `None` when the message is not a feedback report, the
/// machine-readable part is absent, or the mandatory `Feedback-Type` field is
/// missing — fail closed, never infer a complaint that was not reported.
pub fn parse(message: &[u8]) -> Option<ParsedReport> {
	let end = message.len().min(MAX_PARSE);
	let text = String::from_utf8_lossy(&message[..end]);
	let lower = text.to_ascii_lowercase();

	// Must declare itself a feedback report at the top level.
	if !lower.contains("report-type=feedback-report") {
		return None;
	}

	// Locate the machine-readable part and the blank line ending its headers.
	let part = lower.find("message/feedback-report")?;
	let after = &text[part..];
	let body_start = after
		.find("\r\n\r\n")
		.map(|i| i + 4)
		.or_else(|| after.find("\n\n").map(|i| i + 2))?;
	let body = &after[body_start..];

	let mut feedback_type = None;
	let mut original_mail_from = None;
	let mut source_ip = None;
	let mut reported_domain = None;
	let mut arrival_date = None;

	for raw in body.lines() {
		let line = raw.trim_end_matches('\r');
		// A boundary ends the field block.
		if line.starts_with("--") {
			break;
		}
		if line.is_empty() {
			continue;
		}
		let Some((key, value)) = line.split_once(':') else {
			continue;
		};
		let value = value.trim().to_string();
		if value.is_empty() {
			continue;
		}
		match key.trim().to_ascii_lowercase().as_str() {
			"feedback-type" => feedback_type = Some(value),
			"original-mail-from" => original_mail_from = Some(value),
			"source-ip" => source_ip = Some(value),
			"reported-domain" => reported_domain = Some(value),
			"arrival-date" => arrival_date = Some(value),
			_ => {}
		}
	}

	Some(ParsedReport {
		feedback_type: feedback_type?,
		original_mail_from,
		source_ip,
		reported_domain,
		arrival_date,
	})
}

#[cfg(test)]
mod tests;
