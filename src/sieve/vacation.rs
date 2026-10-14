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
	/// An HTML alternative, sent as `multipart/alternative` together with
	/// `reason` (the text part) when present. The JMAP `VacationResponse`
	/// carries both bodies; the Sieve `vacation` extension does not, so this
	/// is always `None` from a Sieve script.
	pub html_body: Option<&'a str>,
}

/// What the reply threads under: the original message's `Subject`,
/// `Message-ID` and `References`, all attacker-written.
#[derive(Default)]
pub struct Original<'a> {
	/// The original `Subject`, used for `Auto: <subject>`.
	pub subject: Option<&'a str>,
	/// The original `Message-ID`, which becomes `In-Reply-To`.
	pub message_id: Option<&'a str>,
	/// The original `References`, extended into the reply's own.
	pub references: Option<&'a str>,
}

/// Most message ids carried over from the original `References`.
const MAX_REFERENCES: usize = 20;

/// Build the vacation reply to `original_sender`, or `None` when an address
/// cannot be written as a header.
///
/// The reply uses the null reverse-path (MAIL FROM `<>`) so an auto-reply can
/// never trigger another, carries `Auto-Submitted: auto-replied` (RFC 3834
/// section 5) and, when the original had a Message-ID, `In-Reply-To` and
/// `References`. The bodies go through the MIME writer: line endings become
/// CRLF, long or non-ASCII lines are quoted-printable, and an HTML body sits
/// next to the text in a `multipart/alternative` whose boundary its content
/// cannot close.
pub fn build_response(
	vacation: &Vacation,
	original_sender: &str,
	original: &Original,
	now: std::time::SystemTime,
) -> Option<AcceptedMessage> {
	use crate::compose::{Bodies, Leaf, address_list, structured, unstructured};
	let from = vacation.from.unwrap_or(vacation.user_address);
	// Reflected back from the original message (Subject, Message-ID): a raw
	// CRLF in any of these values would inject forged headers into the reply.
	let subject = match vacation.subject {
		Some(subject) => sanitize_header_value(subject),
		None => match original.subject {
			Some(original) => format!("Auto: {}", sanitize_header_value(original)),
			None => "Auto: Re: your message".to_string(),
		},
	};
	let mut headers = vec![
		address_list("From", &[format!("<{}>", sanitize_header_value(from))]).ok()?,
		address_list(
			"To",
			&[format!("<{}>", sanitize_header_value(original_sender))],
		)
		.ok()?,
		unstructured("Subject", &subject).ok()?,
		structured("Date", &clock::rfc5322(now)).ok()?,
		structured("Auto-Submitted", "auto-replied (vacation)").ok()?,
	];
	if let Some(id) = original
		.message_id
		.and_then(|value| message_ids(value).next())
	{
		let mut references: Vec<&str> = original
			.references
			.map(message_ids)
			.into_iter()
			.flatten()
			.collect();
		references.drain(..references.len().saturating_sub(MAX_REFERENCES));
		references.push(id);
		headers.extend(structured("In-Reply-To", id).ok());
		headers.extend(structured("References", &references.join(" ")).ok());
	}
	let html = vacation.html_body.map(|html| Leaf::text("html", html));
	let text = (!vacation.reason.is_empty() || html.is_none())
		.then(|| Leaf::text("plain", vacation.reason));
	let root = Bodies {
		text,
		html,
		..Bodies::default()
	}
	.assemble();
	let data = crate::compose::write(&headers, &root).ok()?;
	Some(AcceptedMessage {
		// Null reverse-path: auto-replies must not generate bounces or loops.
		reverse_path: String::new(),
		recipients: vec![original_sender.to_string()],
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	})
}

/// The `<id>` tokens of a header value, each without spaces, controls or
/// nested brackets: whatever else the sender put there is dropped. One
/// pass over the value: each `<` starts a segment that ends at the next
/// `<`, so no byte is looked at twice however the brackets are arranged.
fn message_ids(value: &str) -> impl Iterator<Item = &str> {
	let mut offset = 0;
	value
		.split('<')
		.enumerate()
		.filter_map(move |(index, segment)| {
			let start = offset;
			offset += segment.len() + 1;
			if index == 0 {
				return None;
			}
			let (inner, _) = segment.split_once('>')?;
			let clean = !inner.is_empty()
				&& inner.len() <= 248
				&& inner.bytes().all(|b| b.is_ascii_graphic());
			// `start - 1` is the `<` this segment followed.
			clean.then(|| &value[start - 1..start + inner.len() + 1])
		})
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
			html_body: None,
		}
	}

	#[test]
	fn builds_auto_reply_with_null_sender() {
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: Some("Lunch?"),
				message_id: Some("<abc@example.net>"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
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
			html_body: None,
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: Some("Hi"),
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Out of office"), "{body}");
		assert!(body.contains("From: <assistant@example.org>"), "{body}");
		// No Message-ID on the original → no In-Reply-To.
		assert!(!body.contains("In-Reply-To:"), "{body}");
	}

	#[test]
	fn default_subject_without_original() {
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Auto: Re: your message"), "{body}");
	}

	#[test]
	fn html_body_produces_multipart_alternative() {
		let vacation = Vacation {
			reason: "Away.",
			subject: None,
			from: None,
			user_address: "alice@example.org",
			html_body: Some("<p>Away.</p>"),
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("multipart/alternative"), "{body}");
		assert!(body.contains("text/plain"), "{body}");
		assert!(body.contains("<p>Away.</p>"), "{body}");
	}

	#[test]
	fn subject_with_crlf_does_not_inject_headers() {
		// The original message's Subject carries CRLF and a forged Bcc. The
		// built reply must not contain a header that starts a line.
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: Some("foo\r\nBcc: attacker@evil.example"),
				message_id: Some("<abc@example.net>"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
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
			&Original {
				subject: Some("Lunch?"),
				message_id: Some("<abc@example.net>\r\nBcc: attacker@evil.example"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
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
			html_body: None,
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		let subject_line = body
			.lines()
			.find(|line| line.starts_with("Subject:"))
			.expect("Subject line present");
		assert!(!subject_line.contains('\r'), "{subject_line}");
		assert!(!subject_line.contains('\n'), "{subject_line}");
	}

	/// A `References` or `Message-ID` of a megabyte of `<` with no `>`: each
	/// opening bracket must not rescan the rest of the header, or one
	/// inbound message costs about 5 * 10^11 byte comparisons.
	#[test]
	fn a_header_full_of_open_brackets_costs_linear_time() {
		let hostile = "<".repeat(1 << 20);
		let (done, finished) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			let original = Original {
				subject: None,
				message_id: Some(&hostile),
				references: Some(&hostile),
			};
			let reply = build_response(&vacation(), "bob@example.net", &original, UNIX_EPOCH);
			let _ = done.send(reply.is_some());
		});
		let built = finished
			.recv_timeout(std::time::Duration::from_secs(10))
			.expect("the reply is built in linear time");
		assert!(built, "the reply is still sent, without In-Reply-To");
	}

	#[test]
	fn references_keep_the_last_ids_and_drop_junk() {
		let many: String = (0..40)
			.map(|n| format!("<{n}@x> junk < bad id> "))
			.collect();
		let original = Original {
			subject: None,
			message_id: Some("noise <last@x> more"),
			references: Some(&many),
		};
		let reply =
			build_response(&vacation(), "bob@example.net", &original, UNIX_EPOCH).expect("reply");
		let text = String::from_utf8(reply.data).expect("utf-8");
		let unfolded = text.replace("\r\n ", " ");
		let line = unfolded
			.lines()
			.find(|line| line.starts_with("References:"))
			.expect("References line");
		let ids: Vec<&str> = line["References:".len()..].split_whitespace().collect();
		assert_eq!(ids.len(), MAX_REFERENCES + 1, "{line}");
		assert_eq!(ids[0], "<20@x>");
		assert_eq!(ids[MAX_REFERENCES], "<last@x>");
		assert!(text.contains("In-Reply-To: <last@x>\r\n"), "{text}");
	}
}
