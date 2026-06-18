use super::parse::parse_astring;
use super::{
	Command, ParseError, ReturnOpt, SearchKey, SortKey, parse_imap_date, parse_sequence_set,
};
use crate::imap::mailbox::Flag;

/// Parse `SORT (<keys>) <charset> <search-criteria>` (RFC 5256).
pub(super) fn parse_sort(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let rest = args.trim().strip_prefix('(').ok_or_else(bad)?;
	let (key_list, after) = rest.split_once(')').ok_or_else(bad)?;
	let keys = parse_sort_keys(key_list).ok_or_else(bad)?;

	// A charset token precedes the search criteria; we only support UTF-8/US-ASCII
	// semantics but accept any token and ignore it.
	let (_charset, criteria_text) = after.trim_start().split_once(' ').ok_or_else(bad)?;
	let mut criteria = Vec::new();
	let mut remaining = criteria_text.trim();
	while !remaining.is_empty() {
		let (key, next) = parse_search_key(remaining).ok_or_else(bad)?;
		criteria.push(key);
		remaining = next.trim_start();
	}
	if keys.is_empty() || criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Sort {
		keys,
		criteria,
		uid,
	})
}

/// Parse `THREAD <algorithm> <charset> <search-criteria>` (RFC 5256). Only the
/// ORDEREDSUBJECT algorithm is supported.
pub(super) fn parse_thread(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (algorithm, after) = args.trim().split_once(' ').ok_or_else(bad)?;
	if !algorithm.eq_ignore_ascii_case("ORDEREDSUBJECT") {
		return Err(bad());
	}
	// A charset token precedes the search criteria; accept and ignore it.
	let (_charset, criteria_text) = after.trim_start().split_once(' ').ok_or_else(bad)?;
	let mut criteria = Vec::new();
	let mut remaining = criteria_text.trim();
	while !remaining.is_empty() {
		let (key, next) = parse_search_key(remaining).ok_or_else(bad)?;
		criteria.push(key);
		remaining = next.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Thread { criteria, uid })
}

fn parse_sort_keys(text: &str) -> Option<Vec<(bool, SortKey)>> {
	let mut keys = Vec::new();
	let mut reverse = false;
	for token in text.split_whitespace() {
		let key = match token.to_ascii_uppercase().as_str() {
			"REVERSE" => {
				reverse = true;
				continue;
			}
			"ARRIVAL" => SortKey::Arrival,
			"CC" => SortKey::Cc,
			"DATE" => SortKey::Date,
			"FROM" => SortKey::From,
			"SIZE" => SortKey::Size,
			"SUBJECT" => SortKey::Subject,
			"TO" => SortKey::To,
			_ => return None,
		};
		keys.push((reverse, key));
		reverse = false;
	}
	// A trailing REVERSE with no key is malformed.
	if reverse { None } else { Some(keys) }
}

pub(super) fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut rest = args.trim();

	// Optional ESEARCH `RETURN (...)` block (RFC 4731), before the criteria.
	let mut return_opts = None;
	if let Some(after_return) = strip_keyword(rest, "RETURN") {
		let inner = after_return.trim_start();
		let close = find_close_paren(inner).ok_or_else(bad)?;
		if !inner.starts_with('(') {
			return Err(bad());
		}
		return_opts = Some(parse_return_opts(&inner[1..close]).ok_or_else(bad)?);
		rest = inner[close + 1..].trim_start();
	}

	let mut criteria = Vec::new();
	while !rest.is_empty() {
		let (key, after) = parse_search_key(rest).ok_or_else(bad)?;
		criteria.push(key);
		rest = after.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Search {
		criteria,
		uid,
		return_opts,
	})
}

/// Parse the contents of `RETURN (...)`. An empty list defaults to ALL.
fn parse_return_opts(text: &str) -> Option<Vec<ReturnOpt>> {
	let mut opts = Vec::new();
	for token in text.split_whitespace() {
		opts.push(match token.to_ascii_uppercase().as_str() {
			"MIN" => ReturnOpt::Min,
			"MAX" => ReturnOpt::Max,
			"COUNT" => ReturnOpt::Count,
			"ALL" => ReturnOpt::All,
			_ => return None,
		});
	}
	if opts.is_empty() {
		opts.push(ReturnOpt::All);
	}
	Some(opts)
}

/// If `s` begins with `keyword` (case-insensitive) followed by whitespace,
/// return the remainder.
fn strip_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
	let rest = s.get(..keyword.len())?;
	if rest.eq_ignore_ascii_case(keyword) {
		let tail = &s[keyword.len()..];
		if tail.starts_with(char::is_whitespace) {
			return Some(tail);
		}
	}
	None
}

/// Parse one search-key from the start of `s`, return `(key, remaining)`.
pub(super) fn parse_search_key(s: &str) -> Option<(SearchKey, &str)> {
	if s.starts_with('(') {
		let close = find_close_paren(s)?;
		let inner = s[1..close].trim();
		let after = s[close + 1..].trim_start();
		let mut keys = Vec::new();
		let mut inner_rest = inner;
		while !inner_rest.is_empty() {
			let (key, rest) = parse_search_key(inner_rest)?;
			keys.push(key);
			inner_rest = rest.trim_start();
		}
		return Some((SearchKey::And(keys), after));
	}

	let (word, after) = match s.find(|c: char| c.is_ascii_whitespace() || c == '(') {
		Some(i) => (&s[..i], s[i..].trim_start()),
		None => (s, ""),
	};
	let upper = word.to_ascii_uppercase();

	let (key, rest) = match upper.as_str() {
		"ALL" => (SearchKey::All, after),
		"SEEN" => (SearchKey::FlagIs(Flag::Seen, true), after),
		"UNSEEN" => (SearchKey::FlagIs(Flag::Seen, false), after),
		"DELETED" => (SearchKey::FlagIs(Flag::Deleted, true), after),
		"UNDELETED" => (SearchKey::FlagIs(Flag::Deleted, false), after),
		"FLAGGED" => (SearchKey::FlagIs(Flag::Flagged, true), after),
		"UNFLAGGED" => (SearchKey::FlagIs(Flag::Flagged, false), after),
		"ANSWERED" => (SearchKey::FlagIs(Flag::Answered, true), after),
		"UNANSWERED" => (SearchKey::FlagIs(Flag::Answered, false), after),
		"DRAFT" => (SearchKey::FlagIs(Flag::Draft, true), after),
		"UNDRAFT" => (SearchKey::FlagIs(Flag::Draft, false), after),
		"FROM" | "TO" | "SUBJECT" | "CC" | "BCC" => {
			let (needle, rest) = parse_astring(after)?;
			(
				SearchKey::Header(upper.to_ascii_lowercase(), needle.to_ascii_lowercase()),
				rest.trim_start(),
			)
		}
		// Generic header search: HEADER <field-name> <value>.
		"HEADER" => {
			let (field, rest) = parse_astring(after)?;
			let (value, rest) = parse_astring(rest.trim_start())?;
			(
				SearchKey::Header(field.to_ascii_lowercase(), value.to_ascii_lowercase()),
				rest.trim_start(),
			)
		}
		"TEXT" => {
			let (needle, rest) = parse_astring(after)?;
			(
				SearchKey::Text(needle.to_ascii_lowercase()),
				rest.trim_start(),
			)
		}
		"UID" => {
			let (set_text, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((t, r)) => (t, r.trim_start()),
				None => (after, ""),
			};
			let set = parse_sequence_set(set_text)?;
			(SearchKey::UidSet(set), rest)
		}
		"OR" => {
			let (key1, rest1) = parse_search_key(after.trim_start())?;
			let (key2, rest2) = parse_search_key(rest1.trim_start())?;
			(SearchKey::Or(Box::new(key1), Box::new(key2)), rest2)
		}
		"NOT" => {
			let (key, rest) = parse_search_key(after.trim_start())?;
			(SearchKey::Not(Box::new(key)), rest)
		}
		"BEFORE" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::Before(y, m, d), rest)
		}
		"SINCE" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::Since(y, m, d), rest)
		}
		"ON" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::On(y, m, d), rest)
		}
		"LARGER" => {
			let (n_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((n, r)) => (n, r.trim_start()),
				None => (after, ""),
			};
			let n: u32 = n_str.parse().ok()?;
			(SearchKey::Larger(n), rest)
		}
		"SMALLER" => {
			let (n_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((n, r)) => (n, r.trim_start()),
				None => (after, ""),
			};
			let n: u32 = n_str.parse().ok()?;
			(SearchKey::Smaller(n), rest)
		}
		_ => {
			let set = parse_sequence_set(word)?;
			(SearchKey::Sequence(set), after)
		}
	};
	Some((key, rest))
}

/// Find the index of the `)` that closes the `(` at position 0 of `s`.
fn find_close_paren(s: &str) -> Option<usize> {
	let mut depth = 0usize;
	for (i, c) in s.char_indices() {
		match c {
			'(' => depth += 1,
			')' => {
				depth -= 1;
				if depth == 0 {
					return Some(i);
				}
			}
			_ => {}
		}
	}
	None
}
