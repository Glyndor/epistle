//! RFC 2047 encoded-word decoding for unstructured header values.
//!
//! A header value with any non-ASCII character travels as one or more
//! `=?charset?encoding?text?=` words. Code that searches a `Subject:` for a
//! plain-text marker has to look at the decoded form, or every subject with
//! an accent hides the marker.
//!
//! The decoder is deliberately narrow:
//!
//! - encodings `B` (base64) and `Q` (the quoted-printable variant of
//!   section 4.2), in either case;
//! - charsets `UTF-8`, `US-ASCII` and `ISO-8859-1`, in either case, with an
//!   optional RFC 2231 `*language` suffix. A word in any other charset is
//!   left exactly as it arrived;
//! - a malformed word (unterminated, empty part, invalid base64, a dangling
//!   `=` in Q text, bytes that are not valid in the declared charset) is
//!   left exactly as it arrived. Nothing here returns an error or panics;
//! - whitespace between two adjacent decoded words is dropped (section 6.2),
//!   so a marker split across two words by the sending client is whole again;
//! - a word whose decoded form would be longer than its encoded form is left
//!   as it arrived, so the output is never longer than the input.
//!
//! The output is attacker-controlled text and may contain any character,
//! including CR and LF. Pass it through
//! [`crate::util::header::sanitize_header_value`] before writing it into a
//! header.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Decode every well-formed RFC 2047 encoded-word in `input` and return the
/// result. Text outside encoded-words, and any word this decoder does not
/// handle, is copied through unchanged. The result is never longer than
/// `input`.
pub fn decode(input: &str) -> String {
	let mut out = String::with_capacity(input.len());
	let mut rest = input;
	// True while the last piece written was a decoded word: whitespace that
	// separates it from another decoded word is not part of the text.
	let mut after_word = false;
	while !rest.is_empty() {
		let tail = rest.trim_start_matches(is_linear_whitespace);
		let gap = &rest[..rest.len() - tail.len()];
		if let Some((text, consumed)) = decode_word_at(tail) {
			if !after_word {
				out.push_str(gap);
			}
			out.push_str(&text);
			after_word = true;
			rest = &tail[consumed..];
			continue;
		}
		out.push_str(gap);
		let literal = literal_len(tail);
		out.push_str(&tail[..literal]);
		if literal > 0 {
			after_word = false;
		}
		rest = &tail[literal..];
	}
	out
}

fn is_linear_whitespace(c: char) -> bool {
	matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Length in bytes of the run of `text` that is copied through as is: up to
/// the next whitespace or the next `=?`, and always at least one character
/// when `text` is not empty so the caller makes progress.
fn literal_len(text: &str) -> usize {
	text.char_indices()
		.skip(1)
		.find(|&(index, c)| is_linear_whitespace(c) || text[index..].starts_with("=?"))
		.map_or(text.len(), |(index, _)| index)
}

/// Decode one encoded-word at the very start of `text`. Returns the decoded
/// text and the number of bytes of `text` the word occupied, or `None` when
/// `text` does not start with a word this decoder handles.
fn decode_word_at(text: &str) -> Option<(String, usize)> {
	let body = text.strip_prefix("=?")?;
	let (charset, body) = body.split_once('?')?;
	let (encoding, body) = body.split_once('?')?;
	let (payload, body) = body.split_once('?')?;
	if !body.starts_with('=') {
		return None;
	}
	// Every part is printable ASCII with no whitespace; an empty part is
	// malformed.
	if [charset, encoding, payload]
		.iter()
		.any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_graphic()))
	{
		return None;
	}
	let bytes = match encoding {
		"B" | "b" => BASE64.decode(payload).ok()?,
		"Q" | "q" => decode_q(payload)?,
		_ => return None,
	};
	let decoded = bytes_to_text(charset, bytes)?;
	// "=?" + charset + "?" + encoding + "?" + payload + "?="
	let consumed = 2 + charset.len() + 1 + encoding.len() + 1 + payload.len() + 2;
	(decoded.len() <= consumed).then_some((decoded, consumed))
}

/// The `Q` encoding of RFC 2047 section 4.2: `_` is a space, `=XX` is the
/// byte with that hexadecimal value, anything else stands for itself. `None`
/// for a `=` that is not followed by two hexadecimal digits.
fn decode_q(payload: &str) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(payload.len());
	let mut bytes = payload.bytes();
	while let Some(byte) = bytes.next() {
		match byte {
			b'_' => out.push(b' '),
			b'=' => {
				let high = hex_value(bytes.next()?)?;
				let low = hex_value(bytes.next()?)?;
				out.push((high << 4) | low);
			}
			other => out.push(other),
		}
	}
	Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

/// Interpret `bytes` in `charset`. `None` for a charset this decoder does
/// not handle, or for bytes that are not valid in the declared charset.
fn bytes_to_text(charset: &str, bytes: Vec<u8>) -> Option<String> {
	// RFC 2231 section 5 allows `charset*language`; the language is not
	// needed to decode.
	let name = charset.split('*').next().unwrap_or(charset);
	if name.eq_ignore_ascii_case("utf-8") {
		String::from_utf8(bytes).ok()
	} else if name.eq_ignore_ascii_case("us-ascii") {
		bytes
			.is_ascii()
			.then(|| String::from_utf8(bytes).ok())
			.flatten()
	} else if name.eq_ignore_ascii_case("iso-8859-1") {
		Some(bytes.into_iter().map(char::from).collect())
	} else {
		None
	}
}

#[cfg(test)]
#[path = "encoded_word_tests.rs"]
mod tests;
