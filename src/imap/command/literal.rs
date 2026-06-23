//! Parsing for the literal-bearing commands APPEND (RFC 9051) and REPLACE
//! (RFC 8508). Both end in a `{n}` / `{n+}` octet count whose payload the
//! network layer collects after the command line.

use super::parse::{MAX_APPEND_SIZE, parse_astring};
use super::{Command, ParseError};

/// Parse `APPEND <mailbox> [(flags)] [date] {literal}`. The optional date is
/// accepted and ignored.
pub(super) fn parse_append(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let (flags, size) = parse_flags_and_literal(rest.trim(), &bad)?;
	Ok(Command::Append {
		mailbox,
		flags,
		size,
	})
}

/// Parse `REPLACE <seq> <mailbox> [(flags)] [date] {literal}` (RFC 8508).
/// `uid` selects `UID REPLACE`, where the sequence is a UID.
pub(super) fn parse_replace(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (seq_token, rest) = args.trim().split_once(' ').ok_or_else(bad)?;
	// REPLACE targets exactly one message; a set or `*` is not allowed.
	let sequence: u32 = seq_token.parse().map_err(|_| bad())?;
	if sequence == 0 {
		return Err(bad());
	}
	let (mailbox, rest) = parse_astring(rest.trim()).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let (flags, size) = parse_flags_and_literal(rest.trim(), &bad)?;
	Ok(Command::Replace {
		sequence,
		mailbox,
		flags,
		size,
		uid,
	})
}

/// Parse an optional `(flags)` group followed by the `{n}` / `{n+}` literal
/// count shared by APPEND and REPLACE.
fn parse_flags_and_literal(
	rest: &str,
	bad: &impl Fn() -> ParseError,
) -> Result<(Vec<String>, usize), ParseError> {
	let (flags, literal_text) = if let Some(after) = rest.strip_prefix('(') {
		let (inside, after) = after.split_once(')').ok_or_else(bad)?;
		(
			inside
				.split_whitespace()
				.map(|token| token.to_string())
				.collect(),
			after.trim(),
		)
	} else {
		(Vec::new(), rest)
	};

	let size_text = literal_text
		.strip_prefix('{')
		.and_then(|t| t.strip_suffix('}'))
		.ok_or_else(bad)?;
	let size_text = size_text.strip_suffix('+').unwrap_or(size_text);
	let size: usize = size_text.parse().map_err(|_| bad())?;
	if size == 0 || size > MAX_APPEND_SIZE {
		return Err(bad());
	}
	Ok((flags, size))
}
