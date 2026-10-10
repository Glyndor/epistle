/// What FETCH must return per message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
	/// `FLAGS`: the message's flag list.
	Flags,
	/// RFC 5322 envelope.
	Envelope,
	/// MIME structure, with optional extension fields.
	Structure {
		/// Include BODYSTRUCTURE extension fields.
		extensions: bool,
	},
	/// `RFC822.SIZE`: the RFC 5322 size in octets.
	Rfc822Size,
	/// `UID`: the message's UID.
	Uid,
	/// `BODY[]` / `RFC822`: the full raw message.
	Body,
	/// RFC822 whole message alias.
	Rfc822,
	/// RFC822.HEADER alias, without a Seen transition.
	Rfc822Header,
	/// RFC822.TEXT alias, with a Seen transition.
	Rfc822Text,
	/// A numbered or named body section, optionally partial.
	Section(super::FetchSection),
	/// `BINARY[]`: the body decoded per its Content-Transfer-Encoding (RFC 3516).
	Binary,
	/// `BINARY.SIZE[]`: the decoded body's size in octets (RFC 3516).
	BinarySize,
	/// `INTERNALDATE`: the message's internal date.
	InternalDate,
	/// `MODSEQ`: the message's mod-sequence (CONDSTORE, RFC 7162).
	ModSeq,
	/// `EMAILID`: the message's stable object id (RFC 8474).
	EmailId,
	/// `THREADID`: the message's thread id (RFC 8474); singleton == EMAILID.
	ThreadId,
	/// `SAVEDATE`: when the message was saved to the mailbox (RFC 8514).
	SaveDate,
	/// `PREVIEW`: a short text snippet of the message (RFC 8970).
	Preview,
}

use super::*;

pub(super) fn parse_fetch(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (sequence_text, items_text) = args.split_once(' ').ok_or_else(bad)?;
	let sequence = parse_sequence_set(sequence_text).ok_or_else(bad)?;

	let items_text = items_text.trim();
	let (items_group, modifier) = split_items(items_text).ok_or_else(bad)?;
	let (changed_since, vanished) = parse_fetch_modifier(modifier, tag)?;
	// VANISHED is only valid on UID FETCH with CHANGEDSINCE (RFC 7162 §3.1.4.1).
	if vanished && (!uid || changed_since.is_none()) {
		return Err(bad());
	}
	let inner = items_group
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.unwrap_or(items_group);
	let mut items = Vec::new();
	for word in super::fetch_section::tokens(inner).ok_or_else(bad)? {
		match word.to_ascii_uppercase().as_str() {
			"FLAGS" => items.push(FetchItem::Flags),
			"ENVELOPE" => items.push(FetchItem::Envelope),
			"BODY" => items.push(FetchItem::Structure { extensions: false }),
			"BODYSTRUCTURE" => items.push(FetchItem::Structure { extensions: true }),
			"RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
			"UID" => items.push(FetchItem::Uid),
			"INTERNALDATE" => items.push(FetchItem::InternalDate),
			"MODSEQ" => items.push(FetchItem::ModSeq),
			"EMAILID" => items.push(FetchItem::EmailId),
			"THREADID" => items.push(FetchItem::ThreadId),
			"SAVEDATE" => items.push(FetchItem::SaveDate),
			"PREVIEW" => items.push(FetchItem::Preview),
			"BODY[]" => items.push(FetchItem::Body),
			"RFC822" => items.push(FetchItem::Rfc822),
			"RFC822.HEADER" => items.push(FetchItem::Rfc822Header),
			"RFC822.TEXT" => items.push(FetchItem::Rfc822Text),
			"BINARY[]" => items.push(FetchItem::Binary),
			"BINARY.SIZE[]" => items.push(FetchItem::BinarySize),
			"ALL" | "FULL" => {
				items.extend([
					FetchItem::Flags,
					FetchItem::InternalDate,
					FetchItem::Rfc822Size,
					FetchItem::Envelope,
				]);
				if word.eq_ignore_ascii_case("FULL") {
					items.push(FetchItem::Structure { extensions: false });
				}
			}
			"FAST" => {
				items.extend([
					FetchItem::Flags,
					FetchItem::InternalDate,
					FetchItem::Rfc822Size,
				]);
			}
			_ => items.push(FetchItem::Section(
				super::fetch_section::parse(word).ok_or_else(bad)?,
			)),
		}
	}
	if items.is_empty() {
		return Err(bad());
	}
	// UID FETCH must always report the UID (RFC 9051).
	if uid && !items.contains(&FetchItem::Uid) {
		items.push(FetchItem::Uid);
	}
	if changed_since.is_some() && !items.contains(&FetchItem::ModSeq) {
		items.push(FetchItem::ModSeq);
	}
	Ok(Command::Fetch {
		sequence,
		items,
		uid,
		changed_since,
		vanished,
	})
}

/// Parse an optional `(CHANGEDSINCE n [VANISHED])` FETCH modifier, returning the
/// mod-sequence and whether VANISHED was requested (RFC 7162).
fn parse_fetch_modifier(modifier: &str, tag: &str) -> Result<(Option<u64>, bool), ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	if modifier.is_empty() {
		return Ok((None, false));
	}
	let inner = modifier
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.ok_or_else(bad)?;
	let mut parts = inner.split_whitespace();
	let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
		return Err(bad());
	};
	if !key.eq_ignore_ascii_case("CHANGEDSINCE") {
		return Err(bad());
	}
	let changed_since = Some(value.parse().map_err(|_| bad())?);
	let vanished = match parts.next() {
		None => false,
		Some(tok) if tok.eq_ignore_ascii_case("VANISHED") => true,
		Some(_) => return Err(bad()),
	};
	if parts.next().is_some() {
		return Err(bad());
	}
	Ok((changed_since, vanished))
}

fn split_items(input: &str) -> Option<(&str, &str)> {
	if input.starts_with('(') {
		let mut depth = 0usize;
		let mut quoted = false;
		let mut escaped = false;
		for (i, ch) in input.char_indices() {
			if escaped {
				escaped = false;
				continue;
			}
			if ch == '\\' && quoted {
				escaped = true;
				continue;
			}
			if ch == '"' {
				quoted = !quoted;
			}
			if !quoted {
				if ch == '(' {
					depth += 1;
				}
				if ch == ')' {
					depth = depth.checked_sub(1)?;
					if depth == 0 {
						return Some((&input[..=i], input[i + 1..].trim()));
					}
				}
			}
		}
		None
	} else {
		let first = super::fetch_section::tokens(input)?.into_iter().next()?;
		Some((first, input[first.len()..].trim()))
	}
}
