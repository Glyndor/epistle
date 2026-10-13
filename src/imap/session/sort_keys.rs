//! Per-message keys shared by SORT and THREAD (RFC 5256): the sent date and
//! the INTERNALDATE as instants, and the address keys.

use super::helpers::header_value_raw;
use super::mailbox::MessageRef;
use mail_parser::{Addr, Address, HeaderValue, parsers::MessageStream};
use std::time::{SystemTime, UNIX_EPOCH};

/// INTERNALDATE as seconds since the Unix epoch (negative before it).
pub(super) fn internal_seconds(message: &MessageRef) -> i64 {
	seconds(message.internal_date)
}

/// The RFC 5256 §2.2 sent date of `message`, whose text is `text`: the
/// Date header converted to UTC, or the INTERNALDATE when the header is
/// missing or does not parse.
pub(super) fn sent_seconds(text: &str, message: &MessageRef) -> i64 {
	date_header_seconds(text).unwrap_or_else(|| internal_seconds(message))
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

/// The RFC 5256 §3 key of an address field (FROM, TO, CC): the mailbox
/// (local part) of its first address, uppercased for the i;ascii-casemap
/// comparison. A group comes first as its start marker, whose mailbox is
/// the group name, as in the ENVELOPE. Empty when the field is missing or
/// holds no address.
pub(super) fn address_key(message: &str, field: &str) -> String {
	let Some(mut value) = header_value_raw(message, field) else {
		return String::new();
	};
	value.push_str("\r\n");
	let mailbox = match MessageStream::new(value.as_bytes()).parse_address() {
		HeaderValue::Address(Address::List(items)) => items.first().map(local_part),
		HeaderValue::Address(Address::Group(groups)) => {
			groups.first().and_then(|group| match &group.name {
				Some(name) => Some(name.to_string()),
				None => group.addresses.first().map(local_part),
			})
		}
		_ => None,
	};
	mailbox.unwrap_or_default().to_ascii_uppercase()
}

/// The local part of an address, without a source route.
fn local_part(addr: &Addr<'_>) -> String {
	let address = addr.address.as_deref().unwrap_or_default();
	let address = match address.split_once(':') {
		Some((route, rest)) if route.starts_with('@') => rest,
		_ => address,
	};
	address
		.rsplit_once('@')
		.map_or(address, |(local, _)| local)
		.to_string()
}

fn seconds(time: SystemTime) -> i64 {
	match time.duration_since(UNIX_EPOCH) {
		Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
		Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
	}
}

#[cfg(test)]
mod tests {
	use super::{address_key, date_header_seconds};

	#[test]
	fn the_address_key_is_the_first_mailbox() {
		let key = |value: &str| address_key(&format!("From: {value}\r\n\r\nx\r\n"), "from");
		assert_eq!(key("Foo Bar <user2@domain2.org>, a@b.org"), "USER2");
		assert_eq!(key("user2@domain2.org (foo bar)"), "USER2");
		assert_eq!(key("user2: blah@domain1.org;"), "USER2");
		assert_eq!(key("<@route.org:local@host.org>"), "LOCAL");
		assert_eq!(address_key("Subject: x\r\n\r\n", "from"), "");
	}

	#[test]
	fn the_date_header_is_read_in_utc() {
		let message = "Date: Fri, 22 Feb 2008 10:00:00 +0500\r\n\r\nx\r\n";
		// 2008-02-22T05:00:00Z.
		assert_eq!(date_header_seconds(message), Some(1_203_656_400));
		assert_eq!(date_header_seconds("Date: someday\r\n\r\n"), None);
		assert_eq!(date_header_seconds("Subject: x\r\n\r\n"), None);
	}
}
