//! Delivery Status Notification (bounce) generation, RFC 3464.

use crate::clock;
use crate::queue::reply::parse_enhanced;
use crate::smtp::identification::SYSTEM_AUTO_SUBMITTED as SYSTEM;
use crate::smtp::session::AcceptedMessage;

/// Whether the report is a permanent failure or a transient-delay warning.
#[derive(Clone, Copy)]
enum Kind {
	/// Permanent failure: the message is returned and will not be retried.
	Failed,
	/// Delay warning: the message is still queued and delivery continues.
	Delayed,
}

/// One recipient in a delivery status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRecipient {
	/// The recipient address.
	pub recipient: String,
	/// The remote SMTP reply (`550 5.1.1 ...`), or a local reason when no
	/// server answered.
	pub reason: String,
	/// The host whose reply `reason` is, when a server answered.
	pub remote: Option<String>,
	/// The message expired in the queue rather than being refused.
	pub expired: bool,
}

impl ReportRecipient {
	/// A recipient refused for `reason`, with no remote host to name.
	pub fn new(recipient: &str, reason: &str) -> Self {
		ReportRecipient {
			recipient: recipient.to_string(),
			reason: reason.to_string(),
			remote: None,
			expired: false,
		}
	}
}

/// Build a Delivery Status Notification for a permanently failed message,
/// every recipient failing for the same `reason`.
///
/// Produces an RFC 3464 `multipart/report; report-type=delivery-status`
/// message: a human-readable part, a machine-readable `message/delivery-status`
/// part (per-recipient status), and the original headers. The envelope uses the
/// null reverse-path so a failing DSN can never generate another (loop
/// prevention, RFC 5321 §4.5.5). Returns `None` when the original was itself a
/// bounce.
/// `auto_submitted` writes the `Auto-Submitted: auto-generated` field RFC
/// 3834 asks for on a machine-generated message; `false` leaves it out
/// (the `system_auto_submitted` switch).
pub fn build(
	hostname: &str,
	original_reverse_path: &str,
	failed_recipients: &[String],
	reason: &str,
	original_data: &[u8],
	now: std::time::SystemTime,
	auto_submitted: bool,
) -> Option<AcceptedMessage> {
	let recipients: Vec<ReportRecipient> = failed_recipients
		.iter()
		.map(|recipient| ReportRecipient::new(recipient, reason))
		.collect();
	build_failed(
		hostname,
		original_reverse_path,
		&recipients,
		original_data,
		now,
		auto_submitted,
	)
}

/// Build one failure DSN for a message whose recipients failed each for its
/// own reason: every recipient gets its own `Status`, `Remote-MTA` and
/// `Diagnostic-Code`. See [`build`].
pub fn build_failed(
	hostname: &str,
	original_reverse_path: &str,
	recipients: &[ReportRecipient],
	original_data: &[u8],
	now: std::time::SystemTime,
	auto_submitted: bool,
) -> Option<AcceptedMessage> {
	build_report(
		Kind::Failed,
		hostname,
		original_reverse_path,
		recipients,
		original_data,
		now,
		auto_submitted,
	)
}

/// Build a "delivery delayed" warning DSN (RFC 3464 `Action: delayed`) for the
/// recipients still pending. Unlike a bounce, the message stays queued; this
/// just informs the sender it is taking a while. Returns `None` when the
/// original was itself a bounce.
pub fn build_delay_warning(
	hostname: &str,
	original_reverse_path: &str,
	recipients: &[ReportRecipient],
	original_data: &[u8],
	now: std::time::SystemTime,
	auto_submitted: bool,
) -> Option<AcceptedMessage> {
	build_report(
		Kind::Delayed,
		hostname,
		original_reverse_path,
		recipients,
		original_data,
		now,
		auto_submitted,
	)
}

/// The per-recipient fields of the `message/delivery-status` part
/// (RFC 3464 §2.3).
fn recipient_fields(kind: Kind, recipient: &ReportRecipient, reason: &str) -> String {
	let (action, class) = match kind {
		Kind::Failed => ("failed", 5),
		Kind::Delayed => ("delayed", 4),
	};
	// The status class follows the action, not the reply: a recipient that
	// expired after a 4.2.2 has failed (5.2.2), and one being retried after a
	// 552 5.2.2 is delayed (4.2.2).
	let enhanced = is_smtp_reply(reason)
		.then(|| reason.get(4..).unwrap_or_default().split(' ').next())
		.flatten()
		.and_then(parse_enhanced)
		.filter(|enhanced| reason.starts_with(&enhanced.class.to_string()));
	let status = match enhanced {
		Some(enhanced) => format!("{class}.{}.{}", enhanced.subject, enhanced.detail),
		None if recipient.expired => "5.4.7".to_string(),
		None => format!("{class}.0.0"),
	};
	let mut fields = format!(
		"Final-Recipient: rfc822; {}\r\nAction: {action}\r\nStatus: {status}\r\n",
		recipient.recipient
	);
	if let Some(remote) = &recipient.remote {
		fields.push_str(&format!("Remote-MTA: dns; {}\r\n", sanitize_reason(remote)));
	}
	// Only a server's reply is an SMTP diagnostic; a local reason (no server
	// answered) stays in the human-readable part.
	if is_smtp_reply(reason) {
		fields.push_str(&format!("Diagnostic-Code: smtp; {reason}\r\n"));
	}
	fields.push_str("\r\n");
	fields
}

/// Whether `reason` starts with a three-digit SMTP reply code.
fn is_smtp_reply(reason: &str) -> bool {
	let bytes = reason.as_bytes();
	bytes.len() >= 3
		&& bytes[..3].iter().all(u8::is_ascii_digit)
		&& matches!(bytes[0], b'2'..=b'5')
		&& bytes.get(3).is_none_or(|b| *b == b' ')
}

fn build_report(
	kind: Kind,
	hostname: &str,
	original_reverse_path: &str,
	recipients: &[ReportRecipient],
	original_data: &[u8],
	now: std::time::SystemTime,
	auto_submitted: bool,
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
	let (subject, intro, closing) = match kind {
		Kind::Failed => (
			"Undelivered Mail Returned to Sender",
			"Your message could not be delivered to the following recipients:",
			"The message will not be retried.",
		),
		Kind::Delayed => (
			"Delivery Status Notification (Delay)",
			"Your message is taking longer than expected to deliver to:",
			"No action is required: delivery will keep being retried.",
		),
	};

	let mut human_recipients = String::new();
	let mut per_recipient = String::new();
	for recipient in recipients {
		// The reason is the remote MTA's SMTP reply, attacker-influenced and
		// read with its line breaks intact. Sanitize before it reaches any
		// DSN header or body: a raw CR/LF would inject forged headers into
		// the bounce we send back to the (attacker-chosen) original sender
		// (header injection / DSN smuggling). Collapse all control
		// characters to spaces and cap the length.
		let reason = sanitize_reason(&recipient.reason);
		human_recipients.push_str(&format!("   {}\r\n      {reason}\r\n", recipient.recipient));
		per_recipient.push_str(&recipient_fields(kind, recipient, &reason));
	}

	let original_headers = original_header_block(original_data);
	// The server writes this notice, so it is `auto-generated`: a DSN that
	// claims to be a reply invites an auto-responder to answer a bounce
	// (RFC 3834 section 5).
	let auto = if auto_submitted {
		format!("Auto-Submitted: {SYSTEM}\r\n")
	} else {
		String::new()
	};

	let body = format!(
		"From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
To: <{original_reverse_path}>\r\n\
Subject: {subject}\r\n\
Date: {date}\r\n\
{auto}\
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
		data: crate::util::header_block::frame_generated(body.into_bytes()),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	})
}

/// Sanitize a remote MTA's reply for safe inclusion in a DSN. Every control
/// character (CR, LF, TAB, NUL, …) is replaced with a single space so it cannot
/// break out of a header line or inject new headers, and the result is capped to
/// bound the bounce size. The reply is otherwise attacker-influenced text.
fn sanitize_reason(reason: &str) -> String {
	const MAX_REASON_LEN: usize = 512;
	reason
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.take(MAX_REASON_LEN)
		.collect()
}

/// The header block of the original message (up to the first empty line),
/// capped so a huge message cannot inflate the bounce.
fn original_header_block(data: &[u8]) -> String {
	const MAX_HEADERS: usize = 4096;
	let end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|position| position + 2)
		.unwrap_or(data.len());
	let block = &data[..end];
	// A cut falls on the end of a whole line, never between the two bytes of
	// a line ending.
	let block = match block.len() > MAX_HEADERS {
		true => {
			let cut = &block[..MAX_HEADERS];
			let whole = cut
				.iter()
				.rposition(|byte| *byte == b'\n')
				.map_or(0, |at| at + 1);
			&cut[..whole]
		}
		false => block,
	};
	String::from_utf8_lossy(block).to_string()
}

#[cfg(test)]
#[path = "bounce_tests_framing.rs"]
mod tests_framing;

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
			true,
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
		assert!(body.contains("Auto-Submitted: auto-generated"), "{body}");
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
			true,
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
			true,
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
			true,
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
			&[ReportRecipient::new(
				"bob@elsewhere.example",
				"451 4.4.1 connection timed out",
			)],
			original(),
			UNIX_EPOCH,
			true,
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
				&[ReportRecipient::new("x@y.example", "r")],
				original(),
				UNIX_EPOCH,
				true,
			)
			.is_none()
		);
	}

	#[test]
	fn sanitizes_crlf_in_reason_to_prevent_header_injection() {
		// A hostile/compromised remote MTA returns a reply whose line contains a
		// CRLF and a forged header. It must not appear as a real header (or any
		// new line) in the DSN we generate.
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			"550 rejected\r\nBcc: attacker@evil.example\r\nX-Injected: yes",
			original(),
			UNIX_EPOCH,
			true,
		)
		.expect("bounce built");
		let body = String::from_utf8(bounce.data).expect("ascii");
		// The injected header must never appear at the start of a line.
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		assert!(!body.contains("\r\nX-Injected: yes"), "{body}");
		// The control characters are flattened to spaces, so the reason text is
		// still present on a single line.
		assert!(
			body.contains("550 rejected  Bcc: attacker@evil.example  X-Injected: yes"),
			"{body}"
		);
	}

	#[test]
	fn caps_reason_length() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			&"x".repeat(5_000),
			original(),
			UNIX_EPOCH,
			true,
		)
		.expect("bounce built");
		let body = String::from_utf8(bounce.data).expect("ascii");
		// The reason appears twice (header + text part); each is capped to 512.
		assert!(!body.contains(&"x".repeat(513)), "reason not capped");
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
				true,
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
			true,
		)
		.expect("bounce built");
		assert!(bounce.data.len() < 10_000);
	}
}
