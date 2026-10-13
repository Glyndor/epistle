//! Parsing of one SEARCH `search-key` (RFC 9051 §6.4.4, RFC 3501 §6.4.4).
//! Key names are case-insensitive: the word is upper-cased before matching.

use super::parse::parse_astring;
use super::search::find_close_paren;
use super::{SearchKey, parse_imap_date, parse_sequence_set};
use crate::imap::mailbox::Flag;

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

	let (word, after) = next_token(s);
	let upper = word.to_ascii_uppercase();

	let (key, rest) = match upper.as_str() {
		"ALL" => (SearchKey::All, after),
		"RECENT" => (SearchKey::Recent, after),
		"OLD" => (SearchKey::Not(Box::new(SearchKey::Recent)), after),
		"NEW" => (
			SearchKey::And(vec![
				SearchKey::Recent,
				SearchKey::FlagIs(Flag::Seen, false),
			]),
			after,
		),
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
		// KEYWORD <atom>: matches when the message carries that user keyword
		// (case-insensitive). UNKEYWORD is the negation. Parsed through the
		// generic `FlagIs(Flag::Keyword, bool)` so the same code path the
		// system flags use does the membership test; the keyword's own
		// validator rejects bad atoms here so a malformed token surfaces as
		// a SEARCH parse error rather than a runtime mismatch.
		"KEYWORD" | "UNKEYWORD" => {
			let (needle, rest) = parse_astring(after)?;
			let keyword = Flag::parse(&needle)?;
			if !keyword.is_keyword() {
				return None;
			}
			(
				SearchKey::FlagIs(keyword, upper == "KEYWORD"),
				rest.trim_start(),
			)
		}
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
		"TEXT" | "BODY" => {
			let (needle, rest) = parse_astring(after)?;
			let needle = needle.to_ascii_lowercase();
			let key = if upper == "TEXT" {
				SearchKey::Text(needle)
			} else {
				SearchKey::Body(needle)
			};
			(key, rest.trim_start())
		}
		"UID" => {
			let (set_text, rest) = next_token(after);
			(SearchKey::UidSet(parse_sequence_set(set_text)?), rest)
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
		"BEFORE" | "SINCE" | "ON" | "SENTBEFORE" | "SENTSINCE" | "SENTON" => {
			let (date, rest) = next_token(after);
			// `date` may be quoted (RFC 9051 §9 `date`).
			let date = date
				.strip_prefix('"')
				.and_then(|d| d.strip_suffix('"'))
				.unwrap_or(date);
			let (y, m, d) = parse_imap_date(date)?;
			let key = match upper.as_str() {
				"BEFORE" => SearchKey::Before(y, m, d),
				"SINCE" => SearchKey::Since(y, m, d),
				"ON" => SearchKey::On(y, m, d),
				"SENTBEFORE" => SearchKey::SentBefore(y, m, d),
				"SENTSINCE" => SearchKey::SentSince(y, m, d),
				_ => SearchKey::SentOn(y, m, d),
			};
			(key, rest)
		}
		"LARGER" | "SMALLER" | "YOUNGER" | "OLDER" => {
			let (n_str, rest) = next_token(after);
			let n: u32 = n_str.parse().ok()?;
			let key = match upper.as_str() {
				"LARGER" => SearchKey::Larger(n),
				"SMALLER" => SearchKey::Smaller(n),
				"YOUNGER" => SearchKey::Younger(n),
				_ => SearchKey::Older(n),
			};
			(key, rest)
		}
		"MODSEQ" => parse_modseq(after)?,
		_ => {
			let set = parse_sequence_set(word)?;
			(SearchKey::Sequence(set), after)
		}
	};
	Some((key, rest))
}

/// `MODSEQ [<entry-name> <entry-type-req>] <mod-sequence-valzer>` (RFC 7162
/// §3.1.5). The store keeps one mod-sequence per message, so a metadata entry
/// is checked for syntax and the message's own mod-sequence is compared, as
/// the RFC allows for a server without per-entry mod-sequences.
fn parse_modseq(after: &str) -> Option<(SearchKey, &str)> {
	let mut rest = after;
	if rest.starts_with('"') {
		let (_entry, tail) = parse_astring(rest)?;
		let (entry_type, tail) = next_token(tail.trim_start());
		if !["PRIV", "SHARED", "ALL"]
			.iter()
			.any(|t| entry_type.eq_ignore_ascii_case(t))
		{
			return None;
		}
		rest = tail;
	}
	let (n_str, rest) = next_token(rest);
	Some((SearchKey::ModSeq(n_str.parse().ok()?), rest))
}

/// Split the next whitespace- or `(`-delimited token off `s`, returning it
/// and the remainder with leading whitespace removed.
fn next_token(s: &str) -> (&str, &str) {
	match s.find(|c: char| c.is_ascii_whitespace() || c == '(') {
		Some(i) => (&s[..i], s[i..].trim_start()),
		None => (s, ""),
	}
}
