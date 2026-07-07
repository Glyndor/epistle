//! Parsing for the RFC 5464 METADATA commands GETMETADATA and SETMETADATA.

use super::parse::parse_astring;
use super::{Command, ParseError};

/// Parse `GETMETADATA [(options)] <mailbox> <entry|(entries)>`. Options
/// (MAXSIZE/DEPTH) are accepted and ignored.
pub(super) fn parse_get(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut rest = args.trim_start();
	// Optional leading options group, e.g. `(MAXSIZE 1024)`.
	if rest.starts_with('(') {
		let close = rest.find(')').ok_or_else(bad)?;
		rest = rest[close + 1..].trim_start();
	}
	let (mailbox, after) = parse_astring(rest).ok_or_else(bad)?;
	let after = after.trim_start();
	let entries = if let Some(inner) = after.strip_prefix('(') {
		let close = inner.find(')').ok_or_else(bad)?;
		parse_entry_list(&inner[..close], &bad)?
	} else {
		let (entry, tail) = parse_astring(after).ok_or_else(bad)?;
		if !tail.trim().is_empty() {
			return Err(bad());
		}
		vec![entry]
	};
	if entries.is_empty() {
		return Err(bad());
	}
	Ok(Command::GetMetadata { mailbox, entries })
}

/// Parse `SETMETADATA <mailbox> (entry value entry value ...)`. A value of NIL
/// deletes the entry; otherwise it is an astring.
pub(super) fn parse_set(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, after) = parse_astring(args.trim_start()).ok_or_else(bad)?;
	let after = after.trim_start();
	let inner = after.strip_prefix('(').ok_or_else(bad)?;
	let close = inner.rfind(')').ok_or_else(bad)?;
	let mut body = inner[..close].trim();

	let mut items = Vec::new();
	while !body.is_empty() {
		let (entry, rest) = parse_astring(body).ok_or_else(bad)?;
		let rest = rest.trim_start();
		// The value is NIL (delete) or an astring.
		let (value, rest) = if let Some(tail) = strip_nil(rest) {
			(None, tail)
		} else {
			let (value, tail) = parse_astring(rest).ok_or_else(bad)?;
			(Some(value), tail)
		};
		items.push((entry, value));
		body = rest.trim_start();
	}
	if items.is_empty() {
		return Err(bad());
	}
	Ok(Command::SetMetadata { mailbox, items })
}

/// Parse a whitespace/`-aware list of entry astrings.
fn parse_entry_list(text: &str, bad: &impl Fn() -> ParseError) -> Result<Vec<String>, ParseError> {
	let mut entries = Vec::new();
	let mut rest = text.trim();
	while !rest.is_empty() {
		let (entry, tail) = parse_astring(rest).ok_or_else(bad)?;
		entries.push(entry);
		rest = tail.trim_start();
	}
	Ok(entries)
}

/// If `s` starts with a `NIL` token (case-insensitive, word-bounded), return
/// the remainder.
fn strip_nil(s: &str) -> Option<&str> {
	let rest = s.get(..3)?;
	if rest.eq_ignore_ascii_case("NIL") {
		let tail = &s[3..];
		if tail.is_empty() || tail.starts_with(char::is_whitespace) || tail.starts_with(')') {
			return Some(tail);
		}
	}
	None
}
