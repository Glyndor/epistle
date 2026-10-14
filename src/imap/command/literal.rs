//! Parsing for the literal-bearing commands APPEND (RFC 9051) and REPLACE
//! (RFC 8508). Both end in a `{n}` / `{n+}` octet count whose payload the
//! network layer collects after the command line.

use super::date_time::split_date_time;
use super::parse::{MAX_APPEND_SIZE, parse_astring};
use super::{Command, LiteralAnnouncement, ParseError};
use crate::imap::internal_date::InternalDate;

/// Parse `APPEND <mailbox> [(flags)] [date] {literal}`. The optional date
/// becomes the message's INTERNALDATE.
pub(super) fn parse_append(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let rest = rest.trim();
	let (flags, date, literal) = parse_flags_and_literal(tag, rest, &bad)?;
	let utf8 = utf8_data_item(rest);
	Ok(Command::Append {
		mailbox,
		flags,
		date,
		size: literal.size,
		synchronizing: literal.synchronizing,
		utf8,
		binary: !utf8 && literal8(rest),
	})
}

/// Whether an APPEND tail ends in a literal8 `~{n}` (RFC 3516 §4.4).
fn literal8(tail: &str) -> bool {
	tail.rfind('{')
		.is_some_and(|open| tail[..open].ends_with('~'))
}

/// Whether an APPEND tail ends in the RFC 6855 §4 data item
/// `UTF8 (~{n})`, whose literal is followed by a closing `)`.
fn utf8_data_item(tail: &str) -> bool {
	let Some(open) = tail.rfind('{') else {
		return false;
	};
	let Some(head) = tail[..open].strip_suffix('~') else {
		return false;
	};
	let Some(head) = head.trim_end().strip_suffix('(') else {
		return false;
	};
	let head = head.trim_end();
	let keyword = head
		.len()
		.checked_sub(4)
		.and_then(|start| head.get(start..));
	keyword.is_some_and(|keyword| keyword.eq_ignore_ascii_case("UTF8"))
		&& head[..head.len() - 4]
			.chars()
			.next_back()
			.is_none_or(|c| c == ' ' || c == ')')
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
	let (flags, date, literal) = parse_flags_and_literal(tag, rest.trim(), &bad)?;
	Ok(Command::Replace {
		sequence,
		mailbox,
		flags,
		date,
		size: literal.size,
		uid,
		synchronizing: literal.synchronizing,
	})
}

/// Parse an optional `(flags)` group and an optional quoted date-time
/// followed by the `{n}` / `{n+}` literal count shared by APPEND and REPLACE. The literal's synchronizing flag
/// (the optional `+` after the size) tells the network layer whether the
/// client will already have sent the literal before reading the response
/// (RFC 7888): for the non-synchronizing `{n+}` form the bytes arrive even
/// when the command is rejected, and the server must consume them.
fn parse_flags_and_literal(
	tag: &str,
	rest: &str,
	bad: &impl Fn() -> ParseError,
) -> Result<(Vec<String>, Option<InternalDate>, LiteralAnnouncement), ParseError> {
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

	let (date, literal_text) = split_date_time(literal_text).map_err(|()| bad())?;
	let literal = literal_announcement(literal_text).ok_or_else(bad)?;
	if literal.size == 0 {
		return Err(bad());
	}
	// RFC 7889 §3: a message above the advertised APPENDLIMIT is refused
	// with TOOBIG, which tells the client not to retry it unchanged.
	if literal.size > MAX_APPEND_SIZE {
		return Err(ParseError::TooBig(tag.to_string()));
	}
	Ok((flags, date, literal))
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

/// The literal a continuation line announces, if any: the line that follows
/// a literal inside the same command, such as the next message of a
/// MULTIAPPEND (`(\Seen) {12+}`).
pub(crate) fn literal_announcement_in_tail(line: &str) -> Option<LiteralAnnouncement> {
	literal_announcement(line)
}

/// Find the literal announcement in a full tagged command line, but only
/// for commands that actually carry literals (`APPEND`, `REPLACE` and
/// `UID REPLACE`). The parser may have rejected the line; in that case the
/// session uses this to know how many bytes (RFC 7888 §4) the network
/// layer must discard.
pub(crate) fn literal_announcement_in_line(line: &str) -> Option<LiteralAnnouncement> {
	let (_tag, command) = line.split_once(' ')?;
	let command = match command.split_once(' ') {
		Some((verb, rest)) if verb.eq_ignore_ascii_case("UID") => rest,
		_ => command,
	};
	let (verb, args) = command.split_once(' ')?;
	if !verb.eq_ignore_ascii_case("APPEND") && !verb.eq_ignore_ascii_case("REPLACE") {
		return None;
	}
	literal_announcement(args)
}
