//! Parsing for the literal-bearing commands APPEND (RFC 9051) and REPLACE
//! (RFC 8508). Both end in a `{n}` / `{n+}` octet count whose payload the
//! network layer collects after the command line.

use super::parse::{MAX_APPEND_SIZE, parse_astring};
use super::{Command, LiteralAnnouncement, ParseError};

/// Parse `APPEND <mailbox> [(flags)] [date] {literal}`. The optional date is
/// accepted and ignored.
pub(super) fn parse_append(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let (flags, literal) = parse_flags_and_literal(rest.trim(), &bad)?;
	Ok(Command::Append {
		mailbox,
		flags,
		size: literal.size,
		synchronizing: literal.synchronizing,
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
	let (flags, literal) = parse_flags_and_literal(rest.trim(), &bad)?;
	Ok(Command::Replace {
		sequence,
		mailbox,
		flags,
		size: literal.size,
		uid,
		synchronizing: literal.synchronizing,
	})
}

/// Parse an optional `(flags)` group followed by the `{n}` / `{n+}` literal
/// count shared by APPEND and REPLACE. The literal's synchronizing flag
/// (the optional `+` after the size) tells the network layer whether the
/// client will already have sent the literal before reading the response
/// (RFC 7888): for the non-synchronizing `{n+}` form the bytes arrive even
/// when the command is rejected, and the server must consume them.
fn parse_flags_and_literal(
	rest: &str,
	bad: &impl Fn() -> ParseError,
) -> Result<(Vec<String>, LiteralAnnouncement), ParseError> {
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

	let literal = literal_announcement(literal_text).ok_or_else(bad)?;
	if literal.size == 0 || literal.size > MAX_APPEND_SIZE {
		return Err(bad());
	}
	Ok((flags, literal))
}

/// Pull the trailing `{n}` / `{n+}` size off a literal-bearing command's
/// argument tail. Returns `None` when the tail does not end in a literal
/// announcement, which the parser then reports as `BadArguments`.
pub(super) fn literal_announcement(args: &str) -> Option<LiteralAnnouncement> {
	let inner = args.trim().strip_suffix('}')?;
	let open = inner.rfind('{')?;
	let digits = &inner[open + 1..];
	let (digits, synchronizing) = match digits.strip_suffix('+') {
		Some(rest) => (rest, false),
		None => (digits, true),
	};
	let size = digits.parse().ok()?;
	Some(LiteralAnnouncement {
		size,
		synchronizing,
	})
}

/// Find the literal announcement in a full command line, but only for
/// commands that actually carry literals (`APPEND` / `REPLACE`). The
/// parser may have rejected the line; in that case the session uses this
/// to know how many bytes (RFC 7888 §4) the network layer must discard.
pub(crate) fn literal_announcement_in_line(line: &str) -> Option<LiteralAnnouncement> {
	let (verb, args) = line.split_once(' ')?;
	if !verb.eq_ignore_ascii_case("APPEND") && !verb.eq_ignore_ascii_case("REPLACE") {
		return None;
	}
	literal_announcement(args)
}
