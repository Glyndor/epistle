//! Per-message keys shared by SORT and THREAD (RFC 5256): the sent date and
//! the INTERNALDATE as instants.

use super::helpers::header_value_raw;
use super::mailbox::{MessageRef, Snapshot};
use mail_parser::{HeaderValue, parsers::MessageStream};
use std::time::{SystemTime, UNIX_EPOCH};

/// INTERNALDATE as seconds since the Unix epoch (negative before it).
pub(super) fn internal_seconds(message: &MessageRef) -> i64 {
	seconds(message.internal_date)
}

/// The RFC 5256 §2.2 sent date: the Date header converted to UTC, or the
/// INTERNALDATE when the header is missing or does not parse.
pub(super) fn sent_seconds(snapshot: &Snapshot, message: &MessageRef) -> i64 {
	let raw = snapshot.read(message).unwrap_or_default();
	date_header_seconds(&String::from_utf8_lossy(&raw)).unwrap_or_else(|| internal_seconds(message))
}

/// The first Date header of `message` as a UTC instant.
fn date_header_seconds(message: &str) -> Option<i64> {
	let mut value = header_value_raw(message, "date")?;
	value.push_str("\r\n");
	match MessageStream::new(value.as_bytes()).parse_date() {
		HeaderValue::DateTime(date) if date.is_valid() => Some(date.to_timestamp()),
		_ => None,
	}
}

fn seconds(time: SystemTime) -> i64 {
	match time.duration_since(UNIX_EPOCH) {
		Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
		Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
	}
}

#[cfg(test)]
mod tests {
	use super::date_header_seconds;

	#[test]
	fn the_date_header_is_read_in_utc() {
		let message = "Date: Fri, 22 Feb 2008 10:00:00 +0500\r\n\r\nx\r\n";
		// 2008-02-22T05:00:00Z.
		assert_eq!(date_header_seconds(message), Some(1_203_656_400));
		assert_eq!(date_header_seconds("Date: someday\r\n\r\n"), None);
		assert_eq!(date_header_seconds("Subject: x\r\n\r\n"), None);
	}
}
