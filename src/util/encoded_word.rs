//! RFC 2047 encoded-word decoding and encoding for unstructured header
//! values.
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
//! The encoder produces only the `B` form, in UTF-8. A value that is
//! entirely printable ASCII is returned unchanged; anything else becomes one
//! or more `=?UTF-8?B?...?=` words, each at most 75 octets including the
//! delimiters, separated by `\r\n ` when more than one word is needed. The
//! cut between two adjacent words never lands in the middle of a UTF-8
//! character, so every word decodes on its own to well-formed UTF-8.
//!
//! Decoder output is attacker-controlled text and may contain any
//! character, including CR and LF. Pass it through
//! [`crate::util::header::sanitize_header_value`] before writing it into a
//! header. The encoder itself only sees input that has already been
//! sanitized.

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

/// Length of the delimiters that wrap a UTF-8 B encoded-word.
const B_DELIMITER: &str = "=?UTF-8?B?";
const B_TAIL: &str = "?=";

/// Maximum octets of input bytes per encoded-word: a base64 payload is a
/// multiple of four characters, the 75-octet encoded-word limit leaves
/// room for 63 base64 characters, and `63 / 4 * 3 = 45` input bytes
/// encode into a single word.
const MAX_BYTES_PER_WORD: usize = 45;

/// Encode `value` for an unstructured header. A value that is entirely
/// printable ASCII is returned unchanged. Anything else becomes one or more
/// `=?UTF-8?B?...?=` words, each at most 75 octets including the
/// delimiters, joined by `\r\n ` (RFC 5322 folding) when more than one word
/// is needed.
///
/// The cut between two adjacent words never lands in the middle of a UTF-8
/// character: every word decodes on its own to well-formed UTF-8, and the
/// folded output round-trips through [`decode`] back to the input.
pub fn encode(value: &str) -> String {
	if is_printable_ascii(value) {
		return value.to_string();
	}
	let mut out = String::with_capacity(value.len() + value.len() / 3);
	let bytes = value.as_bytes();
	let mut start = 0usize;
	let mut first = true;
	while start < bytes.len() {
		let end = next_word_end(bytes, start);
		let payload = BASE64.encode(&bytes[start..end]);
		if !first {
			out.push_str("\r\n ");
		}
		out.push_str(B_DELIMITER);
		out.push_str(&payload);
		out.push_str(B_TAIL);
		first = false;
		start = end;
	}
	out
}

/// True when every byte of `value` is printable ASCII (0x20-0x7E). No high
/// bit, no control character, no DEL: a value that already fits on a
/// header line as-is does not need an encoded-word at all.
fn is_printable_ascii(value: &str) -> bool {
	value.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Index just past the last byte of the next encoded-word, starting at
/// `start`. The slice `bytes[start..end]` ends on a UTF-8 boundary and
/// holds at most [`MAX_BYTES_PER_WORD`] bytes.
fn next_word_end(bytes: &[u8], start: usize) -> usize {
	let budget = MAX_BYTES_PER_WORD.min(bytes.len() - start);
	let mut end = start + budget;
	while end > start && !is_utf8_char_boundary(bytes, end) {
		end -= 1;
	}
	// The maximum UTF-8 character length is four bytes, so the walk back
	// can never run off the start: the previous character in `bytes` is
	// at least one byte and `start` cannot sit inside it.
	debug_assert!(end > start, "no UTF-8 boundary within MAX_BYTES_PER_WORD");
	end
}

/// True when `index` is a position where a UTF-8 codepoint starts inside
/// `bytes`. The end of `bytes` is always a boundary. The boundary check
/// uses the same rules `str` does to keep the cut between two encoded
/// words inside a codepoint: at `index`, the byte just before must NOT be
/// a UTF-8 continuation byte, otherwise `index` is in the middle of a
/// multi-byte codepoint and a slice ending here would carry a partial
/// character.
fn is_utf8_char_boundary(bytes: &[u8], index: usize) -> bool {
	if index == 0 || index == bytes.len() {
		return true;
	}
	bytes[index] & 0xC0 != 0x80
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
