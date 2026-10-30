//! SEARCH keys that look at one part of the message: the body alone, or the
//! calendar date written in the Date header.

use super::helpers::{date_to_epoch_day, header_value_raw, load_content};
use super::mailbox::{self, Snapshot};
use mail_parser::{HeaderForm, HeaderValue};

/// `BODY`: `needle` (lowercased by the parser) occurs after the header block.
/// `content` is the lowercased message shared by the other keys.
pub(super) fn body_matches(
	needle: &str,
	snapshot: &Snapshot,
	message: &mailbox::MessageRef,
	content: &mut Option<String>,
) -> bool {
	let text = content.get_or_insert_with(|| load_content(snapshot, message));
	body_of(text).contains(needle)
}

/// The text after the blank line that ends the header block, or nothing when
/// the message has no body.
fn body_of(message: &str) -> &str {
	let crlf = message.find("\r\n\r\n").map(|i| i + 4);
	let lf = message.find("\n\n").map(|i| i + 2);
	let start = match (crlf, lf) {
		(Some(a), Some(b)) => a.min(b),
		(a, b) => a.or(b).unwrap_or(message.len()),
	};
	&message[start..]
}

/// The Date header's calendar date as days since the Unix epoch. RFC 9051
/// §6.4.4 compares SENT* keys "disregarding time and timezone", so the date
/// is taken as written, not converted to UTC. `None` when the header is
/// missing or does not parse.
pub(super) fn sent_epoch_day(snapshot: &Snapshot, message: &mailbox::MessageRef) -> Option<i64> {
	let raw = snapshot.read(message).ok()?;
	let text = String::from_utf8_lossy(&raw);
	let mut value = header_value_raw(&text, "date")?;
	value.push_str("\r\n");
	let parsed = HeaderForm::Date.parse(value.as_bytes());
	match parsed.value() {
		HeaderValue::DateTime(date) if date.month != 0 && date.day != 0 => Some(date_to_epoch_day(
			u32::from(date.year),
			date.month,
			date.day,
		)),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
