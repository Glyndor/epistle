//! Delivery Status Notification (bounce) generation, RFC 3464.

use crate::clock;
use crate::smtp::session::AcceptedMessage;

/// Whether the report is a permanent failure or a transient-delay warning.
#[derive(Clone, Copy)]
enum Kind {
	/// Permanent failure: the message is returned and will not be retried.
	Failed,
	/// Delay warning: the message is still queued and delivery continues.
	Delayed,
}

/// Build a Delivery Status Notification for a permanently failed message.
///
/// Produces an RFC 3464 `multipart/report; report-type=delivery-status`
/// message: a human-readable part, a machine-readable `message/delivery-status`
/// part (per-recipient status), and the original headers. The envelope uses the
/// null reverse-path so a failing DSN can never generate another (loop
/// prevention, RFC 5321 §4.5.5). Returns `None` when the original was itself a
/// bounce.
pub fn build(
	hostname: &str,
	original_reverse_path: &str,
	failed_recipients: &[String],
	reason: &str,
	original_data: &[u8],
	now: std::time::SystemTime,
) -> Option<AcceptedMessage> {
	build_report(
		Kind::Failed,
		hostname,
		original_reverse_path,
		failed_recipients,
		reason,
		original_data,
		now,
	)
}

/// Build a "delivery delayed" warning DSN (RFC 3464 `Action: delayed`). Unlike a
/// bounce, the message stays queued; this just informs the sender it is taking a
/// while. Returns `None` when the original was itself a bounce.
pub fn build_delay_warning(
	hostname: &str,
	original_reverse_path: &str,
	recipients: &[String],
	reason: &str,
	original_data: &[u8],
	now: std::time::SystemTime,
) -> Option<AcceptedMessage> {
	build_report(
		Kind::Delayed,
		hostname,
		original_reverse_path,
		recipients,
		reason,
		original_data,
		now,
	)
}

fn build_report(
	kind: Kind,
	hostname: &str,
	original_reverse_path: &str,
	recipients: &[String],
	reason: &str,
	original_data: &[u8],
	now: std::time::SystemTime,
) -> Option<AcceptedMessage> {
	if original_reverse_path.is_empty() {
		// Never bounce a bounce.
		return None;
	}

	let date = clock::rfc5322(now);
	let boundary = format!(
		"=_dsn_{}",
		now.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	);
	let (subject, action, default_status, intro, reason_label, closing) = match kind {
		Kind::Failed => (
			"Undelivered Mail Returned to Sender",
			"failed",
			"5.0.0",
			"Your message could not be delivered to the following recipients:",
			"Reason:",
			"The message will not be retried.",
		),
		Kind::Delayed => (
			"Delivery Status Notification (Delay)",
			"delayed",
			"4.0.0",
			"Your message is taking longer than expected to deliver to:",
			"Reason for the delay:",
			"No action is required: delivery will keep being retried.",
		),
	};
	let status = enhanced_status(reason, default_status);

	let human_recipients: String = recipients
		.iter()
		.map(|recipient| format!("   {recipient}\r\n"))
		.collect();

	// Per-recipient machine-readable status fields.
	let per_recipient: String = recipients
		.iter()
		.map(|recipient| {
			format!(
				"Final-Recipient: rfc822; {recipient}\r\n\
Action: {action}\r\n\
Status: {status}\r\n\
Diagnostic-Code: smtp; {reason}\r\n\
\r\n"
			)
		})
		.collect();

	let original_headers = original_header_block(original_data);

	let body = format!(
		"From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
To: <{original_reverse_path}>\r\n\
Subject: {subject}\r\n\
Date: {date}\r\n\
Auto-Submitted: auto-replied\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=delivery-status;\r\n\
\tboundary=\"{boundary}\"\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
This is the mail system at host {hostname}.\r\n\
\r\n\
{intro}\r\n\
\r\n\
{human_recipients}\
\r\n\
{reason_label}\r\n\
   {reason}\r\n\
\r\n\
{closing}\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; {hostname}\r\n\
\r\n\
{per_recipient}\
--{boundary}\r\n\
Content-Type: message/rfc822-headers\r\n\
\r\n\
{original_headers}\r\n\
--{boundary}--\r\n",
	);

	Some(AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![original_reverse_path.to_string()],
		data: body.into_bytes(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	})
}

/// The enhanced status code (RFC 3463, `class.subject.detail`) carried in the
/// reason, or `default` when none is present.
fn enhanced_status(reason: &str, default: &str) -> String {
	reason
		.split_whitespace()
		.find(|token| is_enhanced_code(token))
		.unwrap_or(default)
		.to_string()
}

fn is_enhanced_code(token: &str) -> bool {
	let parts: Vec<&str> = token.split('.').collect();
	parts.len() == 3
		&& parts
			.iter()
			.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// The header block of the original message (up to the first empty line),
/// capped so a huge message cannot inflate the bounce.
fn original_header_block(data: &[u8]) -> String {
	const MAX_HEADERS: usize = 4096;
	let end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|position| position + 2)
		.unwrap_or(data.len())
		.min(MAX_HEADERS);
	String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::{Duration, UNIX_EPOCH};

	fn original() -> &'static [u8] {
		b"From: alice@example.org\r\nSubject: hi\r\n\r\nsecret body\r\n"
	}

	#[test]
	fn builds_bounce_to_the_sender() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			"550 5.1.1 no such user",
			original(),
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.expect("bounce built");

		assert_eq!(bounce.reverse_path, "");
		assert_eq!(bounce.recipients, vec!["alice@example.org".to_string()]);
		let body = String::from_utf8(bounce.data).expect("ascii");
		assert!(body.contains("MAILER-DAEMON@mail.example.org"), "{body}");
		assert!(body.contains("bob@elsewhere.example"), "{body}");
		assert!(body.contains("550 5.1.1 no such user"), "{body}");
		assert!(body.contains("Subject: hi"), "{body}");
		// The original body must not leak into the bounce.
		assert!(!body.contains("secret body"), "{body}");
		assert!(body.contains("Auto-Submitted: auto-replied"), "{body}");
	}

	#[test]
	fn produces_rfc3464_delivery_status() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			"550 5.1.1 no such user",
			original(),
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.expect("bounce built");
		let body = String::from_utf8(bounce.data).expect("ascii");

		assert!(
			body.contains("Content-Type: multipart/report; report-type=delivery-status"),
			"{body}"
		);
		assert!(
			body.contains("Content-Type: message/delivery-status"),
			"{body}"
		);
		assert!(
			body.contains("Reporting-MTA: dns; mail.example.org"),
			"{body}"
		);
		assert!(
			body.contains("Final-Recipient: rfc822; bob@elsewhere.example"),
			"{body}"
		);
		assert!(body.contains("Action: failed"), "{body}");
		// Enhanced status extracted from the reason.
		assert!(body.contains("Status: 5.1.1"), "{body}");
		assert!(
			body.contains("Diagnostic-Code: smtp; 550 5.1.1 no such user"),
			"{body}"
		);
		assert!(
			body.contains("Content-Type: message/rfc822-headers"),
			"{body}"
		);
		// The closing boundary terminates the report.
		assert!(body.trim_end().ends_with("--"), "{body}");
	}

	#[test]
	fn defaults_status_when_reason_has_no_code() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["b@c.example".to_string()],
			"connection timed out",
			original(),
			UNIX_EPOCH,
		)
		.expect("bounce built");
		let body = String::from_utf8(bounce.data).expect("ascii");
		assert!(body.contains("Status: 5.0.0"), "{body}");
	}

	#[test]
	fn reports_each_failed_recipient() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["b@c.example".to_string(), "d@e.example".to_string()],
			"550 5.2.1 mailbox disabled",
			original(),
			UNIX_EPOCH,
		)
		.expect("bounce built");
		let body = String::from_utf8(bounce.data).expect("ascii");
		assert_eq!(
			body.matches("Final-Recipient: rfc822;").count(),
			2,
			"{body}"
		);
	}

	#[test]
	fn delay_warning_is_transient_and_keeps_retrying() {
		let warning = build_delay_warning(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			"451 4.4.1 connection timed out",
			original(),
			UNIX_EPOCH,
		)
		.expect("warning built");
		assert_eq!(warning.reverse_path, "");
		let body = String::from_utf8(warning.data).expect("ascii");
		assert!(body.contains("Action: delayed"), "{body}");
		assert!(body.contains("Status: 4.4.1"), "{body}");
		assert!(
			body.contains("Subject: Delivery Status Notification (Delay)"),
			"{body}"
		);
		assert!(body.contains("retried"), "{body}");
		// A delayed report must never be returned for a bounce.
		assert!(
			build_delay_warning(
				"h.example",
				"",
				&["x@y.example".to_string()],
				"r",
				original(),
				UNIX_EPOCH
			)
			.is_none()
		);
	}

	#[test]
	fn never_bounces_a_bounce() {
		assert!(
			build(
				"mail.example.org",
				"",
				&["x@example.org".to_string()],
				"reason",
				original(),
				UNIX_EPOCH,
			)
			.is_none()
		);
	}

	#[test]
	fn caps_quoted_headers() {
		let mut huge = b"From: a@example.org\r\n".to_vec();
		huge.extend(std::iter::repeat_n(b'x', 100_000));
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["b@c.example".to_string()],
			"reason",
			&huge,
			UNIX_EPOCH,
		)
		.expect("bounce built");
		assert!(bounce.data.len() < 10_000);
	}
}
