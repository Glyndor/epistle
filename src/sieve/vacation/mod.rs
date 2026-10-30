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
		sender_verified: false,
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
mod tests;
