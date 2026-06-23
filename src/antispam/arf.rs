//! Abuse Reporting Format (ARF) feedback reports, RFC 5965.
//!
//! When a message is reported as abuse, we emit a
//! `multipart/report; report-type=feedback-report` message: a human-readable
//! part, a machine-readable `message/feedback-report` part, and the reported
//! message itself.

use crate::clock;
use crate::smtp::session::AcceptedMessage;

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
	let reported_domain = report
		.original_mail_from
		.rsplit_once('@')
		.map(|(_, domain)| domain)
		.unwrap_or("");

	let mut feedback = format!(
		"Feedback-Type: {}\r\n\
User-Agent: {hostname}\r\n\
Version: 1\r\n\
Original-Mail-From: {}\r\n\
Arrival-Date: {date}\r\n\
Reported-Domain: {reported_domain}\r\n",
		report.feedback_type.as_str(),
		report.original_mail_from,
	);
	if let Some(ip) = report.source_ip {
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
		data: body.into_bytes(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

/// The reported message, truncated to a sane size for embedding.
fn embed(message: &[u8]) -> String {
	let end = message.len().min(MAX_EMBEDDED);
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
mod tests {
	use super::*;
	use std::time::{Duration, UNIX_EPOCH};

	const REPORTED: &[u8] = b"From: spammer@bad.example\r\nSubject: buy now\r\n\r\nspam body\r\n";

	fn report() -> Report<'static> {
		Report {
			report_to: "abuse@isp.example",
			feedback_type: FeedbackType::Abuse,
			original_mail_from: "spammer@bad.example",
			source_ip: Some("192.0.2.5"),
			reported_message: REPORTED,
		}
	}

	#[test]
	fn builds_feedback_report() {
		let msg = build(
			"mail.example.org",
			&report(),
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		);
		assert_eq!(msg.reverse_path, "");
		assert_eq!(msg.recipients, vec!["abuse@isp.example".to_string()]);
		let body = String::from_utf8(msg.data).expect("ascii");

		assert!(
			body.contains("Content-Type: multipart/report; report-type=feedback-report"),
			"{body}"
		);
		assert!(
			body.contains("Content-Type: message/feedback-report"),
			"{body}"
		);
		assert!(body.contains("Feedback-Type: abuse"), "{body}");
		assert!(body.contains("Version: 1"), "{body}");
		assert!(
			body.contains("Original-Mail-From: spammer@bad.example"),
			"{body}"
		);
		assert!(body.contains("Reported-Domain: bad.example"), "{body}");
		assert!(body.contains("Source-IP: 192.0.2.5"), "{body}");
		// The reported message is embedded.
		assert!(body.contains("Subject: buy now"), "{body}");
		assert!(body.trim_end().ends_with("--"), "{body}");
	}

	#[test]
	fn omits_source_ip_when_unknown() {
		let mut report = report();
		report.source_ip = None;
		let body =
			String::from_utf8(build("mail.example.org", &report, UNIX_EPOCH).data).expect("ascii");
		assert!(!body.contains("Source-IP:"), "{body}");
	}

	#[test]
	fn caps_embedded_message() {
		let mut huge = b"From: a@bad.example\r\n\r\n".to_vec();
		huge.extend(std::iter::repeat_n(b'x', 200_000));
		let mut report = report();
		report.reported_message = &huge;
		let msg = build("mail.example.org", &report, UNIX_EPOCH);
		assert!(msg.data.len() < 60_000);
	}

	#[test]
	fn other_feedback_type_renders() {
		let mut report = report();
		report.feedback_type = FeedbackType::Other;
		let body =
			String::from_utf8(build("mail.example.org", &report, UNIX_EPOCH).data).expect("ascii");
		assert!(body.contains("Feedback-Type: other"), "{body}");
	}

	#[test]
	fn parses_what_it_builds() {
		let built = build("mail.example.org", &report(), UNIX_EPOCH);
		let parsed = parse(&built.data).expect("our own report parses");
		assert_eq!(parsed.feedback_type, "abuse");
		assert_eq!(
			parsed.original_mail_from.as_deref(),
			Some("spammer@bad.example")
		);
		assert_eq!(parsed.source_ip.as_deref(), Some("192.0.2.5"));
		assert_eq!(parsed.reported_domain.as_deref(), Some("bad.example"));
	}

	#[test]
	fn parses_external_report_with_lf_only() {
		let raw = b"Content-Type: multipart/report; report-type=feedback-report;\n\
\tboundary=\"b\"\n\
\n\
--b\n\
Content-Type: message/feedback-report\n\
\n\
Feedback-Type: fraud\n\
Original-Mail-From: phish@evil.example\n\
\n\
--b--\n";
		let parsed = parse(raw).expect("lf-only report parses");
		assert_eq!(parsed.feedback_type, "fraud");
		assert_eq!(
			parsed.original_mail_from.as_deref(),
			Some("phish@evil.example")
		);
		assert_eq!(parsed.source_ip, None);
	}

	#[test]
	fn rejects_non_report_message() {
		let plain = b"From: a@example\r\nSubject: hi\r\n\r\nnot a report\r\n";
		assert_eq!(parse(plain), None);
	}

	#[test]
	fn rejects_empty_input() {
		assert_eq!(parse(b""), None);
	}

	#[test]
	fn rejects_report_without_feedback_type() {
		// Declares the report type but the machine part lacks Feedback-Type.
		let raw =
			b"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Original-Mail-From: spammer@bad.example\r\n\
\r\n\
--b--\r\n";
		assert_eq!(parse(raw), None);
	}

	#[test]
	fn rejects_report_type_without_machine_part() {
		// Has the top-level marker but no message/feedback-report part.
		let raw =
			b"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
human only\r\n\
--b--\r\n";
		assert_eq!(parse(raw), None);
	}
}
