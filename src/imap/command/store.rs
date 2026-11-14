//! The STORE command: how it changes the flag set (RFC 9051 §6.4).

use super::sequence_set::parse_sequence_set;
use super::{Command, ParseError};

/// How STORE changes the flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
	/// `FLAGS`: replace the flag set.
	Set,
	/// `+FLAGS`: add the listed flags.
	Add,
	/// `-FLAGS`: remove the listed flags.
	Remove,
}

/// Parse `STORE <sequence> (<mode> <flags>)` (RFC 9051 §6.4). The optional
/// `(UNCHANGEDSINCE n)` modifier (CONDSTORE, RFC 7162) is accepted too.
pub(super) fn parse_store(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (sequence_text, rest) = args.split_once(' ').ok_or_else(bad)?;
	let sequence = parse_sequence_set(sequence_text).ok_or_else(bad)?;

	// Optional leading `(UNCHANGEDSINCE n)` modifier (RFC 7162).
	let rest = rest.trim();
	let (unchanged_since, rest) = if rest.starts_with('(') {
		let close = rest.find(')').ok_or_else(bad)?;
		let mut parts = rest[1..close].split_whitespace();
		let value = match (parts.next(), parts.next(), parts.next()) {
			(Some(key), Some(value), None) if key.eq_ignore_ascii_case("UNCHANGEDSINCE") => {
				value.parse().map_err(|_| bad())?
			}
			_ => return Err(bad()),
		};
		(Some(value), rest[close + 1..].trim())
	} else {
		(None, rest)
	};

	let (item, flags_text) = rest.split_once(' ').ok_or_else(bad)?;
	let item = item.to_ascii_uppercase();
	let (mode, silent) = match item.as_str() {
		"FLAGS" => (StoreMode::Set, false),
		"FLAGS.SILENT" => (StoreMode::Set, true),
		"+FLAGS" => (StoreMode::Add, false),
		"+FLAGS.SILENT" => (StoreMode::Add, true),
		"-FLAGS" => (StoreMode::Remove, false),
		"-FLAGS.SILENT" => (StoreMode::Remove, true),
		_ => return Err(bad()),
	};

	let flags_text = flags_text.trim();
	let inner = flags_text
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.unwrap_or(flags_text);
	let flags: Vec<String> = inner
		.split_whitespace()
		.map(|token| token.to_string())
		.collect();
	Ok(Command::Store {
		sequence,
		mode,
		flags,
		silent,
		uid,
		unchanged_since,
	})
}
