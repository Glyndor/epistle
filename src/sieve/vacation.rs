//! Sieve `vacation` autoresponder (RFC 5230): build the reply message.
//!
//! This is the pure response builder. The suppression rules (don't reply to
//! bulk/automated mail, reply at most once per sender per `:days`) are applied
//! by the caller before invoking this.

use crate::clock;
use crate::smtp::session::AcceptedMessage;
use crate::util::header::sanitize_header_value;

/// Parameters of a `vacation` action.
pub struct Vacation<'a> {
	/// The reply body (`:reason`).
	pub reason: &'a str,
	/// An explicit `:subject`, else `Auto: <original subject>` is used.
	pub subject: Option<&'a str>,
	/// An explicit `:from`, else the responding user's address.
	pub from: Option<&'a str>,
	/// The responding user's own address.
	pub user_address: &'a str,
}

/// Build the vacation reply to `original_sender`.
///
/// The reply uses the null reverse-path (MAIL FROM `<>`) so an auto-reply can
/// never trigger another, and carries `Auto-Submitted: auto-replied` plus an
/// `In-Reply-To` when the original had a Message-ID.
pub fn build_response(
	vacation: &Vacation,
	original_sender: &str,
	original_subject: Option<&str>,
	original_message_id: Option<&str>,
	now: std::time::SystemTime,
) -> AcceptedMessage {
	let from = vacation.from.unwrap_or(vacation.user_address);
	// Reflected back from the original message (Subject, Message-ID): a raw
	// CRLF in any of these values would inject forged headers into the reply.
	let subject = match vacation.subject {
		Some(subject) => sanitize_header_value(subject),
		None => match original_subject {
			Some(original) => format!("Auto: {}", sanitize_header_value(original)),
			None => "Auto: Re: your message".to_string(),
		},
	};

	let mut headers = format!(
		"From: <{from}>\r\n\
To: <{original_sender}>\r\n\
Subject: {subject}\r\n\
Date: {date}\r\n\
Auto-Submitted: auto-replied (vacation)\r\n",
		date = clock::rfc5322(now),
	);
	if let Some(message_id) = original_message_id {
		let message_id = sanitize_header_value(message_id);
		headers.push_str(&format!("In-Reply-To: {message_id}\r\n"));
	}

	let body = format!("{headers}\r\n{}\r\n", vacation.reason);

	AcceptedMessage {
		// Null reverse-path: auto-replies must not generate bounces or loops.
		reverse_path: String::new(),
		recipients: vec![original_sender.to_string()],
		data: body.into_bytes(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::UNIX_EPOCH;

	fn vacation() -> Vacation<'static> {
		Vacation {
			reason: "I am away until Monday.",
			subject: None,
			from: None,
			user_address: "alice@example.org",
		}
	}

	#[test]
	fn builds_auto_reply_with_null_sender() {
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			Some("Lunch?"),
			Some("<abc@example.net>"),
			UNIX_EPOCH,
		);
		assert_eq!(reply.reverse_path, "");
		assert_eq!(reply.recipients, vec!["bob@example.net".to_string()]);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("From: <alice@example.org>"), "{body}");
		assert!(body.contains("To: <bob@example.net>"), "{body}");
		assert!(body.contains("Subject: Auto: Lunch?"), "{body}");
		assert!(
			body.contains("Auto-Submitted: auto-replied (vacation)"),
			"{body}"
		);
		assert!(body.contains("In-Reply-To: <abc@example.net>"), "{body}");
		assert!(body.contains("I am away until Monday."), "{body}");
	}

	#[test]
	fn explicit_subject_and_from_override() {
		let vacation = Vacation {
			reason: "Away.",
			subject: Some("Out of office"),
			from: Some("assistant@example.org"),
			user_address: "alice@example.org",
		};
		let reply = build_response(&vacation, "bob@example.net", Some("Hi"), None, UNIX_EPOCH);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Out of office"), "{body}");
		assert!(body.contains("From: <assistant@example.org>"), "{body}");
		// No Message-ID on the original → no In-Reply-To.
		assert!(!body.contains("In-Reply-To:"), "{body}");
	}

	#[test]
	fn default_subject_without_original() {
		let reply = build_response(&vacation(), "bob@example.net", None, None, UNIX_EPOCH);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Auto: Re: your message"), "{body}");
	}

	#[test]
	fn subject_with_crlf_does_not_inject_headers() {
		// The original message's Subject carries CRLF and a forged Bcc. The
		// built reply must not contain a header that starts a line.
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			Some("foo\r\nBcc: attacker@evil.example"),
			Some("<abc@example.net>"),
			UNIX_EPOCH,
		);
		let body = String::from_utf8(reply.data).expect("ascii");
		// No injected header at the start of any line.
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		assert!(!body.contains("\r\nX-Injected:"), "{body}");
		// The Subject line itself must not contain raw CR or LF: the injected
		// CRLF was flattened to spaces, so the value sits on one line.
		let subject_line = body
			.lines()
			.find(|line| line.starts_with("Subject:"))
			.expect("Subject line present");
		assert!(!subject_line.contains('\r'), "{subject_line}");
		assert!(!subject_line.contains('\n'), "{subject_line}");
		assert!(
			subject_line.contains("Bcc: attacker@evil.example"),
			"{subject_line}"
		);
	}

	#[test]
	fn message_id_with_crlf_does_not_inject_headers() {
		// The original message's Message-ID carries CRLF and a forged Bcc.
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			Some("Lunch?"),
			Some("<abc@example.net>\r\nBcc: attacker@evil.example"),
			UNIX_EPOCH,
		);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		let in_reply_to_line = body
			.lines()
			.find(|line| line.starts_with("In-Reply-To:"))
			.expect("In-Reply-To line present");
		assert!(!in_reply_to_line.contains('\r'), "{in_reply_to_line}");
		assert!(!in_reply_to_line.contains('\n'), "{in_reply_to_line}");
	}

	#[test]
	fn explicit_subject_with_crlf_is_flattened() {
		// A Sieve script's `:subject` parameter is also user-influenced: the
		// same flattening must apply regardless of where the value comes from.
		let vacation = Vacation {
			reason: "Away.",
			subject: Some("Out of office\r\nBcc: attacker@evil.example"),
			from: None,
			user_address: "alice@example.org",
		};
		let reply = build_response(&vacation, "bob@example.net", None, None, UNIX_EPOCH);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		let subject_line = body
			.lines()
			.find(|line| line.starts_with("Subject:"))
			.expect("Subject line present");
		assert!(!subject_line.contains('\r'), "{subject_line}");
		assert!(!subject_line.contains('\n'), "{subject_line}");
	}
}
