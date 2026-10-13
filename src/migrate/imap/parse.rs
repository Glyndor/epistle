//! Interpreting the server responses the migration client asks for: status
//! lines, capabilities, LIST/XLIST entries, NAMESPACE, SELECT data and
//! FETCH answers. Every parser walks its token list once.

use std::time::SystemTime;

use super::token::{Token, tokenize};
use super::wire::Response;

/// The status word of a status response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
	/// `OK`.
	Ok,
	/// `NO`.
	No,
	/// `BAD`.
	Bad,
	/// `BYE` (untagged only).
	Bye,
	/// `PREAUTH` (greeting only).
	Preauth,
}

/// What kind of line a response is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
	/// `+ ...`: the server waits for more of the command.
	Continuation,
	/// `<tag> OK|NO|BAD text`.
	Tagged {
		/// The tag.
		tag: Vec<u8>,
		/// The status word.
		status: Status,
		/// The rest of the line (response code and human text).
		text: Vec<u8>,
	},
	/// `* OK|NO|BAD|BYE|PREAUTH text`.
	UntaggedStatus {
		/// The status word.
		status: Status,
		/// The rest of the line.
		text: Vec<u8>,
	},
	/// Any other `*` line (data): CAPABILITY, LIST, FETCH, EXISTS, ...
	Data,
}

/// Classify a response by its first line.
pub(crate) fn kind(response: &Response) -> Kind {
	let head = response.head();
	if head.first() == Some(&b'+') {
		return Kind::Continuation;
	}
	let (first, rest) = split_word(head);
	let (word, text) = split_word(rest);
	let status = status_word(word);
	if first == b"*" {
		return match status {
			Some(status) => Kind::UntaggedStatus {
				status,
				text: text.to_vec(),
			},
			None => Kind::Data,
		};
	}
	match status {
		Some(status) => Kind::Tagged {
			tag: first.to_vec(),
			status,
			text: text.to_vec(),
		},
		None => Kind::Data,
	}
}

fn status_word(word: &[u8]) -> Option<Status> {
	Some(match word.to_ascii_uppercase().as_slice() {
		b"OK" => Status::Ok,
		b"NO" => Status::No,
		b"BAD" => Status::Bad,
		b"BYE" => Status::Bye,
		b"PREAUTH" => Status::Preauth,
		_ => return None,
	})
}

/// Split off the first space-separated word.
fn split_word(text: &[u8]) -> (&[u8], &[u8]) {
	match text.iter().position(|&b| b == b' ') {
		Some(at) => (&text[..at], &text[at + 1..]),
		None => (text, &[]),
	}
}

/// The response code at the start of a status text (`[UIDVALIDITY 7]`), as
/// its words. Empty when the text has none.
pub(crate) fn response_code(text: &[u8]) -> Vec<String> {
	let Some(inner) = text.strip_prefix(b"[") else {
		return Vec::new();
	};
	let Some(end) = inner.iter().position(|&b| b == b']') else {
		return Vec::new();
	};
	String::from_utf8_lossy(&inner[..end])
		.split_ascii_whitespace()
		.map(str::to_string)
		.collect()
}

/// The capability names in a CAPABILITY data line or response code,
/// uppercased. `words` starts at the word `CAPABILITY`.
pub(crate) fn capabilities<'a>(words: impl Iterator<Item = &'a str>) -> Vec<String> {
	words.skip(1).map(str::to_ascii_uppercase).collect()
}

/// The words of a data line (`* CAPABILITY ...`, `* 3 EXISTS`) after the
/// `*`.
pub(crate) fn data_words(response: &Response) -> Vec<String> {
	String::from_utf8_lossy(response.head())
		.split_ascii_whitespace()
		.skip(1)
		.take(512)
		.map(str::to_string)
		.collect()
}

/// One LIST or XLIST entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListEntry {
	/// The mailbox attributes, lowercased (`\noselect`, `\sent`).
	pub(crate) attributes: Vec<String>,
	/// The hierarchy delimiter, `None` for a flat namespace.
	pub(crate) delimiter: Option<u8>,
	/// The mailbox name as sent.
	pub(crate) name: Vec<u8>,
}

/// Why a data response could not be understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the server sent a malformed {0} response")]
pub(crate) struct Malformed(pub(crate) &'static str);

/// Parse `* LIST (attrs) delim name` (or XLIST). `None` for any other line.
pub(crate) fn list_entry(response: &Response) -> Result<Option<ListEntry>, Malformed> {
	let bad = || Malformed("LIST");
	let tokens = tokenize(response).map_err(|_| bad())?;
	let mut iter = tokens.iter();
	if !iter.next().is_some_and(|t| t.is_atom("*")) {
		return Ok(None);
	}
	if !iter
		.next()
		.is_some_and(|t| t.is_atom("LIST") || t.is_atom("XLIST"))
	{
		return Ok(None);
	}
	if iter.next() != Some(&Token::Open) {
		return Err(bad());
	}
	let mut attributes = Vec::new();
	loop {
		match iter.next().ok_or_else(bad)? {
			Token::Close => break,
			Token::Atom(atom) => {
				attributes.push(String::from_utf8_lossy(atom).to_ascii_lowercase());
			}
			_ => return Err(bad()),
		}
	}
	let delimiter = match iter.next().ok_or_else(bad)? {
		Token::Quoted(value) if value.len() == 1 => Some(value[0]),
		token if token.is_atom("NIL") => None,
		_ => return Err(bad()),
	};
	let name = iter
		.next()
		.and_then(|token| match token {
			Token::Open | Token::Close => None,
			token => token.bytes().map(<[u8]>::to_vec),
		})
		.ok_or_else(bad)?;
	Ok(Some(ListEntry {
		attributes,
		delimiter,
		name,
	}))
}

/// The prefix of the first personal namespace in `* NAMESPACE ...`, if the
/// server announced one. `None` for any other line or `NIL`.
pub(crate) fn personal_namespace(response: &Response) -> Option<Vec<u8>> {
	let tokens = tokenize(response).ok()?;
	let mut iter = tokens.iter();
	if !(iter.next()?.is_atom("*") && iter.next()?.is_atom("NAMESPACE")) {
		return None;
	}
	if iter.next()? != &Token::Open || iter.next()? != &Token::Open {
		return None;
	}
	match iter.next()? {
		Token::Quoted(prefix) => Some(prefix.clone()),
		Token::Literal(prefix, _) => Some(prefix.to_vec()),
		_ => None,
	}
}

/// One message as the listing step sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Listed {
	/// The message UID.
	pub(crate) uid: u32,
	/// Its RFC822.SIZE.
	pub(crate) size: u64,
}

/// One message as a body fetch returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fetched {
	/// The message UID.
	pub(crate) uid: u32,
	/// The flags as sent, without case folding.
	pub(crate) flags: Vec<String>,
	/// The INTERNALDATE, when present and well formed.
	pub(crate) internal_date: Option<SystemTime>,
	/// The RFC822.SIZE the server claimed.
	pub(crate) size: Option<u64>,
	/// The message octets.
	pub(crate) body: Option<Vec<u8>>,
}

/// Parse `* N FETCH (...)`. `None` for any other line.
pub(crate) fn fetch(mut response: Response) -> Result<Option<Fetched>, Malformed> {
	let bad = || Malformed("FETCH");
	let (fetched, body_segment) = {
		let tokens = tokenize(&response).map_err(|_| bad())?;
		let is_fetch = tokens.len() >= 3
			&& tokens[0].is_atom("*")
			&& tokens[2].is_atom("FETCH")
			&& matches!(tokens[1], Token::Atom(n) if n.iter().all(u8::is_ascii_digit));
		if !is_fetch {
			return Ok(None);
		}
		if tokens.get(3) != Some(&Token::Open) || tokens.last() != Some(&Token::Close) {
			return Err(bad());
		}
		fetch_items(&tokens[4..tokens.len() - 1])?
	};
	let mut fetched = fetched;
	if let Some(index) = body_segment {
		fetched.body = response
			.segments
			.get_mut(index)
			.and_then(|segment| segment.literal.take());
	}
	Ok(Some(fetched))
}

/// Walk the `key value` pairs inside a FETCH list. Returns the parsed
/// items and the segment holding the body literal, if the body came as one.
fn fetch_items(items: &[Token<'_>]) -> Result<(Fetched, Option<usize>), Malformed> {
	let bad = || Malformed("FETCH");
	let mut fetched = Fetched {
		uid: 0,
		flags: Vec::new(),
		internal_date: None,
		size: None,
		body: None,
	};
	let mut body_segment = None;
	let mut at = 0;
	while at < items.len() {
		let Token::Atom(key) = &items[at] else {
			return Err(bad());
		};
		let key = key.to_ascii_uppercase();
		let value = items.get(at + 1).ok_or_else(bad)?;
		at += 2;
		match key.as_slice() {
			b"UID" => fetched.uid = number(value).ok_or_else(bad)?,
			b"RFC822.SIZE" => fetched.size = Some(number(value).ok_or_else(bad)?),
			b"INTERNALDATE" => {
				fetched.internal_date = value
					.bytes()
					.and_then(|bytes| std::str::from_utf8(bytes).ok())
					.and_then(crate::imap::command::parse_date_time);
			}
			b"FLAGS" => {
				if value != &Token::Open {
					return Err(bad());
				}
				loop {
					match items.get(at).ok_or_else(bad)? {
						Token::Close => break,
						Token::Atom(flag) => {
							fetched
								.flags
								.push(String::from_utf8_lossy(flag).into_owned());
						}
						_ => return Err(bad()),
					}
					at += 1;
				}
				at += 1;
			}
			b"BODY[]" | b"RFC822" => match value {
				Token::Literal(_, segment) => body_segment = Some(*segment),
				Token::Quoted(bytes) => fetched.body = Some(bytes.clone()),
				token if token.is_atom("NIL") => {}
				_ => return Err(bad()),
			},
			_ => at = skip_value(items, at - 1).ok_or_else(bad)?,
		}
	}
	Ok((fetched, body_segment))
}

/// The index just past the value starting at `at`: one token, or a whole
/// parenthesized list.
fn skip_value(items: &[Token<'_>], at: usize) -> Option<usize> {
	if items.get(at)? != &Token::Open {
		return Some(at + 1);
	}
	let mut depth = 0usize;
	for (offset, token) in items[at..].iter().enumerate() {
		match token {
			Token::Open => depth += 1,
			Token::Close => {
				depth -= 1;
				if depth == 0 {
					return Some(at + offset + 1);
				}
			}
			_ => {}
		}
	}
	None
}

/// A decimal number token.
fn number<T: std::str::FromStr>(token: &Token<'_>) -> Option<T> {
	match token {
		Token::Atom(digits) if digits.iter().all(u8::is_ascii_digit) => {
			std::str::from_utf8(digits).ok()?.parse().ok()
		}
		_ => None,
	}
}

/// Parse the listing answer `* N FETCH (UID u RFC822.SIZE s)`.
pub(crate) fn listed(response: Response) -> Result<Option<Listed>, Malformed> {
	let Some(fetched) = fetch(response)? else {
		return Ok(None);
	};
	match (fetched.uid, fetched.size) {
		(0, _) | (_, None) => Ok(None),
		(uid, Some(size)) => Ok(Some(Listed { uid, size })),
	}
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
