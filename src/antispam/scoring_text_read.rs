//! How the parts of a message are read into the window: what a person sees
//! when the bytes are not plain UTF-8.
//!
//! A text part in UTF-16 is a stream of letters with a zero byte between
//! them, and one in Latin-1 has a lone byte where an accented letter is; read
//! as UTF-8 the first has no word in it and the second is cut at every accent.
//! The part is read as UTF-8 as always, and, only when it is not valid UTF-8
//! or has zero bytes in it, again the way its bytes would be shown. The
//! headers are read as they are and, where they carry RFC 2047 encoded words,
//! decoded.

use mail_parser::{Addr, Address, HeaderValue, MessageParser};

use super::Window;

/// Longest token the classifier takes, in bytes.
const MAX_TOKEN: usize = 30;

/// Most charsets of one part that are looked at.
const MAX_CHARSETS: usize = 4;

/// Feed a decoded part to `window`: as UTF-8, and, when it is not plain UTF-8
/// text or a charset it declares says UTF-16, under each of the other readings
/// a client could use. A reading is added, never put in place of another: a
/// charset the part claims is the sender's word, and the bytes may be read
/// otherwise by the client.
pub(super) fn push_part(window: &mut Window, bytes: &[u8], charsets: &[String]) {
	window.push_bytes(bytes);
	let declared: Vec<Option<bool>> = charsets
		.iter()
		.take(MAX_CHARSETS)
		.filter_map(|charset| declared_order(charset))
		.collect();
	let eight_bit = bytes.contains(&0) || std::str::from_utf8(bytes).is_err();
	if declared.is_empty() && !eight_bit {
		return;
	}
	// The orders to read as UTF-16: the one the bytes show, and each one a
	// charset names. A charset that names none means big endian (RFC 2781)
	// when the bytes show nothing either.
	let shown = utf16_order(bytes);
	let mut orders: Vec<bool> = shown.into_iter().collect();
	for order in declared {
		let little = order.unwrap_or(false);
		if (order.is_some() || shown.is_none()) && !orders.contains(&little) {
			orders.push(little);
		}
	}
	for little in orders {
		let units = bytes.as_chunks::<2>().0.iter().map(|&pair| {
			if little {
				u16::from_le_bytes(pair)
			} else {
				u16::from_be_bytes(pair)
			}
		});
		let chars = char::decode_utf16(units).map(|unit| unit.unwrap_or('\u{fffd}'));
		push_chars(window, chars, false);
	}
	if eight_bit {
		// Latin-1, which any other single-byte charset resembles closely
		// enough to give the same words each time. The words with no accent in
		// them were read already.
		push_chars(window, bytes.iter().map(|&byte| char::from(byte)), true);
	}
}

/// What a charset name says of UTF-16: `None` if it is not UTF-16, else the
/// order it names (`true` little endian), or `Some(None)` when it names none.
fn declared_order(charset: &str) -> Option<Option<bool>> {
	let name = charset.trim().trim_matches('"');
	let rest = name
		.strip_prefix("utf-16")
		.or_else(|| name.strip_prefix("utf16"))
		.or_else(|| name.strip_prefix("ucs-2"))
		.or_else(|| name.strip_prefix("ucs2"))?;
	Some(match rest.trim_start_matches(['-', '_']) {
		"le" => Some(true),
		"be" => Some(false),
		_ => None,
	})
}

/// The byte order of `bytes` read as UTF-16, `true` for little endian, when
/// they look like UTF-16: they start with a byte order mark, or a quarter of
/// the units have a zero where the high byte of an ASCII letter would be.
fn utf16_order(bytes: &[u8]) -> Option<bool> {
	match bytes {
		[0xff, 0xfe, ..] => return Some(true),
		[0xfe, 0xff, ..] => return Some(false),
		_ => {}
	}
	let units = bytes.len() / 2;
	if units == 0 {
		return None;
	}
	let (mut low, mut high) = (0usize, 0usize);
	for pair in bytes.as_chunks::<2>().0 {
		low += usize::from(pair[0] == 0);
		high += usize::from(pair[1] == 0);
	}
	let enough = units.div_ceil(4);
	if high >= enough && high >= low {
		Some(true)
	} else if low >= enough {
		Some(false)
	} else {
		None
	}
}

/// Split `chars` into tokens the way [`Window::push_str`] does and feed them
/// to `window`; with `accented_only`, only the tokens that have a character
/// outside ASCII in them. Holds one token at a time.
pub(super) fn push_chars(
	window: &mut Window,
	chars: impl Iterator<Item = char>,
	accented_only: bool,
) {
	let mut token = String::new();
	let mut too_long = false;
	let mut accented = false;
	for c in chars.chain(std::iter::once(' ')) {
		if is_invisible(c) {
			// It joins the two halves of a word that the UTF-8 reading splits,
			// so the word is new even if it has no accent.
			accented = true;
			continue;
		}
		if c.is_alphanumeric() {
			if token.len() + c.len_utf8() > MAX_TOKEN {
				too_long = true;
			} else if !too_long {
				token.push(c);
			}
			accented |= !c.is_ascii();
			continue;
		}
		if !too_long && token.len() >= 2 && (accented || !accented_only) {
			window.push_token(&token);
		}
		token.clear();
		too_long = false;
		accented = false;
	}
}

/// Whether `c` takes no room on the screen and is no break between words: a
/// zero width space or joiner, a soft hyphen, a byte order mark, a variation
/// selector, a tag character.
pub(super) fn is_invisible(c: char) -> bool {
	matches!(
		c,
		'\u{00ad}'
			| '\u{034f}'
			| '\u{061c}'
			| '\u{115f}'..='\u{1160}'
			| '\u{17b4}'..='\u{17b5}'
			| '\u{180b}'..='\u{180f}'
			| '\u{200b}'..='\u{200f}'
			| '\u{202a}'..='\u{202e}'
			| '\u{2060}'..='\u{206f}'
			| '\u{3164}'
			| '\u{fe00}'..='\u{fe0f}'
			| '\u{feff}'
			| '\u{ffa0}'
			| '\u{e0000}'..='\u{e0fff}'
	)
}

/// Feed the header block to `window`: as it is, and, when it holds encoded
/// words, as a mail client shows it.
pub(super) fn push_header(window: &mut Window, block: &[u8]) {
	window.push_bytes(block);
	if !block.windows(2).any(|pair| pair == b"=?") {
		return;
	}
	let mut block = block.to_vec();
	block.extend_from_slice(b"\r\n");
	let Some(parsed) = MessageParser::new().parse_headers(&block) else {
		return;
	};
	for header in parsed.headers() {
		match &header.value {
			HeaderValue::Text(text) => window.push_str(text),
			HeaderValue::TextList(list) => list.iter().for_each(|text| window.push_str(text)),
			HeaderValue::Address(Address::List(list)) => push_addresses(window, list),
			HeaderValue::Address(Address::Group(groups)) => {
				for group in groups {
					if let Some(name) = &group.name {
						window.push_str(name);
					}
					push_addresses(window, &group.addresses);
				}
			}
			_ => {}
		}
	}
}

fn push_addresses(window: &mut Window, list: &[Addr<'_>]) {
	for addr in list {
		if let Some(name) = &addr.name {
			window.push_str(name);
		}
	}
}
