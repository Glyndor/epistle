//! Size bounds shared by the DMARC and TLS-RPT parsers.
//!
//! Every string and every list a report carries was written by an
//! unauthenticated remote sender. This module is the one place that decides
//! how much of it survives: the file name derived from the organisation
//! name, the length of each free-text field stored in the JSONL record, and
//! the number of list entries a deserialiser is allowed to collect.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};

/// Longest file-name component derived from an organisation name, in bytes.
/// The component is ASCII by construction, so bytes and characters agree.
/// 64 keeps `{org}.jsonl` far below the 255 byte `NAME_MAX` of the common
/// filesystems while still telling two reporters apart.
pub const MAX_FILE_COMPONENT: usize = 64;

/// Longest free-text field kept in a stored record, in characters: the
/// organisation name, report id, contact address, policy domain and
/// `header_from`. A DNS name is at most 253 characters, so 256 holds every
/// legitimate value and stops one field from making a JSONL line megabytes
/// long.
pub const MAX_TEXT: usize = 256;

/// Longest keyword-like field kept in a stored record, in characters: an IP
/// address (45 at most in text form), a disposition, an authentication
/// result, a policy keyword, a TLS-RPT `result-type`, a timestamp.
pub const MAX_KEYWORD: usize = 64;

/// Name used when the organisation name yields no usable file component.
const UNKNOWN: &str = "unknown";

/// Map an organisation name to a single, safe file-name component.
///
/// Guarantees: the result is never empty, is at most [`MAX_FILE_COMPONENT`]
/// bytes, holds only ASCII alphanumerics, `.` and `-` (anything else became
/// `_`), and is never `.`, `..` or any other run of dots, so joining it to
/// a directory cannot leave that directory.
pub fn file_component(name: &str) -> String {
	let mut out = String::with_capacity(name.len().min(MAX_FILE_COMPONENT));
	for c in name.chars() {
		if out.len() >= MAX_FILE_COMPONENT {
			break;
		}
		if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
			out.push(c);
		} else {
			out.push('_');
		}
	}
	if out.is_empty() || out.chars().all(|c| c == '.') {
		return UNKNOWN.to_string();
	}
	out
}

/// Keep at most `max` characters of `text`, cutting on a character boundary,
/// and replace control characters with U+FFFD. The stored value is later
/// printed to an operator's terminal by `epistle reports`, so an escape
/// sequence planted in a report must not survive ingestion.
pub fn cap_text(text: &str, max: usize) -> String {
	text.chars()
		.take(max)
		.map(|c| if c.is_control() { '\u{FFFD}' } else { c })
		.collect()
}

/// [`cap_text`] applied in place.
pub fn cap_in_place(text: &mut String, max: usize) {
	let needs_work = text.chars().count() > max || text.chars().any(char::is_control);
	if needs_work {
		*text = cap_text(text, max);
	}
}

/// Deserialise a list and cap it at `max + 1` entries: enough to detect
/// overflow without parsing a million-row bomb. The caller checks the
/// returned vec's length: `len() > max` means overflow, and the caller
/// truncates and sets a `truncated` flag.
pub(super) fn capped_seq<'de, D, T>(deserializer: D, max: usize) -> Result<Vec<T>, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	struct Capped<T> {
		max: usize,
		marker: PhantomData<T>,
	}

	impl<'de, T: Deserialize<'de>> Visitor<'de> for Capped<T> {
		type Value = Vec<T>;

		fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			write!(formatter, "a list capped at {} entries", self.max)
		}

		fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
			let cap = self.max.saturating_add(1);
			let mut out = Vec::with_capacity(cap.min(8));
			while let Some(item) = seq.next_element::<T>()? {
				if out.len() >= cap {
					break;
				}
				out.push(item);
			}
			Ok(out)
		}
	}

	deserializer.deserialize_seq(Capped {
		max,
		marker: PhantomData,
	})
}

/// Truncate `entries` to `max` items and return `(overflow, kept)`. An
/// empty vec with `max == 0` is treated as not overflowing.
pub(super) fn truncate<T>(entries: Vec<T>, max: usize) -> (bool, Vec<T>) {
	if entries.len() > max {
		let mut kept = entries;
		kept.truncate(max);
		(true, kept)
	} else {
		(false, entries)
	}
}

#[cfg(test)]
#[path = "bounds_tests.rs"]
mod tests;