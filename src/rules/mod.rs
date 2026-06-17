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
mod tests {
	use super::*;

	fn rule(
		domain: Option<&str>,
		header: Option<(&str, &str)>,
		junk: bool,
		mailbox: Option<&str>,
	) -> Rule {
		Rule {
			sender_domain: domain.map(String::from),
			header: header.map(|(n, _)| n.to_string()),
			header_contains: header.map(|(_, v)| v.to_string()),
			junk,
			mailbox: mailbox.map(String::from),
		}
	}

	const MSG: &[u8] =
		b"From: a@news.example\r\nList-Id: <discuss.news.example>\r\nSubject: hi\r\n\r\nbody\r\n";

	#[test]
	fn matches_sender_domain_case_insensitively() {
		let rules = vec![rule(Some("News.Example"), None, false, Some("Lists"))];
		let hit = evaluate(&rules, MSG, Some("news.example")).expect("match");
		assert_eq!(hit.mailbox.as_deref(), Some("Lists"));
	}

	#[test]
	fn matches_header_substring() {
		let rules = vec![rule(None, Some(("List-Id", "discuss")), true, None)];
		let hit = evaluate(&rules, MSG, None).expect("match");
		assert!(hit.junk);
	}

	#[test]
	fn requires_all_conditions() {
		// Right header but wrong domain: no match.
		let rules = vec![rule(
			Some("other.example"),
			Some(("List-Id", "discuss")),
			false,
			Some("X"),
		)];
		assert!(evaluate(&rules, MSG, Some("news.example")).is_none());
	}

	#[test]
	fn first_match_wins() {
		let rules = vec![
			rule(Some("news.example"), None, false, Some("First")),
			rule(Some("news.example"), None, false, Some("Second")),
		];
		assert_eq!(
			evaluate(&rules, MSG, Some("news.example"))
				.unwrap()
				.mailbox
				.as_deref(),
			Some("First")
		);
	}

	#[test]
	fn missing_header_does_not_match() {
		let rules = vec![rule(None, Some(("X-Absent", "z")), true, None)];
		assert!(evaluate(&rules, MSG, None).is_none());
	}

	#[test]
	fn unconditional_rule_never_matches() {
		let rules = vec![rule(None, None, true, Some("All"))];
		assert!(evaluate(&rules, MSG, Some("news.example")).is_none());
	}
}
