//! Delivery rulesets: route or flag inbound mail by sender or header.
//!
//! Each rule states optional conditions (sender domain, a header substring)
//! and an action (mark junk, and/or file into a mailbox). The first rule whose
//! conditions all match wins. Matching is pure so it is fully unit-testable.

use serde::Deserialize;

/// One delivery rule. Conditions are ANDed; an absent condition always matches.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
	/// Match when the verified sender domain equals this (case-insensitive).
	pub sender_domain: Option<String>,
	/// Header name whose value must contain `header_contains`.
	pub header: Option<String>,
	/// Substring required in `header`'s value (case-insensitive).
	pub header_contains: Option<String>,
	/// Mark the message as junk.
	#[serde(default)]
	pub junk: bool,
	/// File the message into this mailbox instead of INBOX.
	pub mailbox: Option<String>,
}

impl Rule {
	fn matches(&self, raw: &[u8], sender_domain: Option<&str>) -> bool {
		if let Some(want) = &self.sender_domain {
			match sender_domain {
				Some(got) if got.eq_ignore_ascii_case(want) => {}
				_ => return false,
			}
		}
		if let (Some(name), Some(needle)) = (&self.header, &self.header_contains) {
			match header_value(raw, name) {
				Some(value)
					if value
						.to_ascii_lowercase()
						.contains(&needle.to_ascii_lowercase()) => {}
				_ => return false,
			}
		}
		// A rule with no conditions at all would match everything; require at
		// least one condition to have been specified.
		self.sender_domain.is_some() || (self.header.is_some() && self.header_contains.is_some())
	}
}

/// The first rule whose conditions all match `message`, if any.
pub fn evaluate<'a>(
	rules: &'a [Rule],
	raw: &[u8],
	sender_domain: Option<&str>,
) -> Option<&'a Rule> {
	rules.iter().find(|rule| rule.matches(raw, sender_domain))
}

/// The value of the first header named `name` (case-insensitive), unfolded to
/// a single line. `None` if absent or the header block is not valid UTF-8.
fn header_value(raw: &[u8], name: &str) -> Option<String> {
	let end = find_header_end(raw).unwrap_or(raw.len());
	let headers = std::str::from_utf8(&raw[..end]).ok()?;
	let prefix = format!("{name}:").to_ascii_lowercase();
	let mut lines = headers.split_inclusive("\r\n").peekable();
	while let Some(line) = lines.next() {
		if line.to_ascii_lowercase().starts_with(&prefix) {
			let mut value = line[prefix.len()..].trim().to_string();
			// Absorb folded continuation lines (start with space/tab).
			while let Some(cont) = lines.peek() {
				if cont.starts_with(' ') || cont.starts_with('\t') {
					value.push(' ');
					value.push_str(cont.trim());
					lines.next();
				} else {
					break;
				}
			}
			return Some(value);
		}
	}
	None
}

/// Index of the end of the header block (the empty line), if present.
fn find_header_end(raw: &[u8]) -> Option<usize> {
	raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2)
}

#[cfg(test)]
mod tests;
