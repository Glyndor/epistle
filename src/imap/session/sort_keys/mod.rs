//! Per-message keys shared by SORT and THREAD (RFC 5256): the sent date and
//! the INTERNALDATE as instants, and the address keys.

use super::helpers::header_value_raw;
use super::mailbox::MessageRef;
use mail_parser::{Address, HeaderForm, HeaderValue, Mailbox};
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
	let parsed = HeaderForm::Date.parse(value.as_bytes());
	match parsed.value() {
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
	let parsed = HeaderForm::Addresses.parse(value.as_bytes());
	let mailbox = match parsed.value() {
		HeaderValue::Address(list) => list.iter().next().and_then(|item| match item {
			Address::Mailbox(addr) => Some(local_part(addr)),
			Address::Group(group) => group
				.name()
				.map(str::to_string)
				.or_else(|| group.mailboxes().next().map(local_part)),
		}),
		_ => None,
	};
	mailbox.unwrap_or_default().to_ascii_uppercase()
}

/// The local part of an address, without a source route.
fn local_part(addr: Mailbox<'_>) -> String {
	let address = addr.address().unwrap_or_default();
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
mod tests;
