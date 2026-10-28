//! Header-name SEARCH keys (`FROM`, `TO`, `CC`, `BCC`, `SUBJECT` and
//! `HEADER <name> <value>`), matched against every field with that name.

use super::mailbox::{self, Snapshot};
use crate::util::encoded_word;
use mail_parser::{Addr, Address, HeaderValue, parsers::MessageStream};

/// Whether any field named `name` contains `needle` (both lowercased by the
/// parser), case-insensitively. An empty needle matches any message that has
/// the field at all, which is how clients test for a header's presence.
///
/// RFC 2047 encoded-words are decoded before comparison, so `Hola` matches a
/// subject stored as `=?UTF-8?B?wqFIb2xhIQ==?=`. Address fields are compared
/// in their parsed form, `Name <local@domain>` per address and
/// `group: members;` per group, so comments and odd spacing inside an address
/// do not hide it from a search for the plain address.
pub(super) fn header_matches(
	name: &str,
	needle: &str,
	snapshot: &Snapshot,
	message: &mailbox::MessageRef,
) -> bool {
	let raw = snapshot.read(message).unwrap_or_default();
	let text = String::from_utf8_lossy(&raw);
	header_values(&text, name).iter().any(|value| {
		if needle.is_empty() {
			return true;
		}
		let haystack = match name {
			"from" | "to" | "cc" | "bcc" => Some(addresses_text(value)).filter(|t| !t.is_empty()),
			_ => None,
		}
		.unwrap_or_else(|| encoded_word::decode(value));
		haystack.to_ascii_lowercase().contains(needle)
	})
}

/// Every field named `name` (ASCII case-insensitive) in the header block,
/// in order, each with its continuation lines unfolded.
fn header_values(message: &str, name: &str) -> Vec<String> {
	let mut values: Vec<String> = Vec::new();
	let mut in_field = false;
	for line in message.lines() {
		if line.is_empty() {
			break;
		}
		if line.starts_with([' ', '\t']) {
			if in_field && let Some(value) = values.last_mut() {
				value.push(' ');
				value.push_str(line.trim());
			}
			continue;
		}
		in_field = false;
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			values.push(value.trim().to_string());
			in_field = true;
		}
	}
	values
}

/// An address field rendered as Dovecot's search compares it: each address
/// as `Name <local@domain>` or bare `local@domain`, each group as
/// `name: members;`, joined by `, `. Empty when nothing parses.
fn addresses_text(value: &str) -> String {
	let input = format!("{value}\r\n");
	let mut parts = Vec::new();
	match MessageStream::new(input.as_bytes()).parse_address() {
		HeaderValue::Address(Address::List(items)) => {
			parts.extend(items.iter().map(address_text));
		}
		HeaderValue::Address(Address::Group(groups)) => {
			for group in groups {
				let members: Vec<String> = group.addresses.iter().map(address_text).collect();
				match &group.name {
					Some(name) => parts.push(format!("{name}: {};", members.join(", "))),
					None => parts.extend(members),
				}
			}
		}
		_ => {}
	}
	parts.join(", ")
}

fn address_text(addr: &Addr<'_>) -> String {
	match (addr.name.as_deref(), addr.address.as_deref()) {
		(Some(name), Some(address)) => format!("{name} <{address}>"),
		(None, Some(address)) => address.to_string(),
		(Some(name), None) => name.to_string(),
		(None, None) => String::new(),
	}
}

#[cfg(test)]
mod tests;
