//! Adapt mail-parser 1.0 to the server's defensive reading of MIME and headers.
//!
//! BINARY must still reject bad transfer encodings, and JMAP must retain
//! the original octets when decoding fails. Encoding::decode in 1.0 is
//! deliberately best-effort and cannot implement either contract.

/// A value made only of decode replacements is not a charset declaration.
/// 1.0 emits it for an extended parameter's incomplete UTF-16 payload; the
/// declaration itself is recovered separately from the original bytes.
/// Keep every other candidate, including obfuscated UTF-16 names: the text
/// scanner deliberately accepts more than the MIME charset label grammar.
pub(crate) fn is_charset_label(label: &str) -> bool {
	label.chars().any(|ch| ch != '\u{fffd}')
}

/// Keep the conservative trust policy for readers that ignore leading colons.
/// mail-parser 1.0 preserves them in unknown names instead of folding them.
pub(crate) fn trust_header_name(name: &str) -> &str {
	name.trim_start_matches(|ch: char| ch == ':' || ch.is_ascii_whitespace())
}

/// The standalone base64 decoder's 0.11.9 behavior, including unpadded
/// final groups, whitespace, repeated padding and its 0xff stop byte.
pub(crate) fn base64_decode(bytes: &[u8]) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(bytes.len().div_ceil(4) * 3);
	let mut chunk = 0u32;
	let mut count = 0;
	for byte in bytes.iter().copied().chain(std::iter::once(0xff)) {
		let value = match byte {
			b'A'..=b'Z' => byte - b'A',
			b'a'..=b'z' => byte - b'a' + 26,
			b'0'..=b'9' => byte - b'0' + 52,
			b'+' => 62,
			b'/' => 63,
			b' ' | b'\t' | b'\r' | b'\n' => continue,
			b'=' | 0xff => {
				match count {
					2 => out.push((chunk >> 4) as u8),
					3 => out.extend_from_slice(&[(chunk >> 10) as u8, (chunk >> 2) as u8]),
					_ => {}
				}
				count = 0;
				if byte == 0xff {
					break;
				}
				continue;
			}
			_ => return None,
		};
		chunk = (chunk << 6) | u32::from(value);
		count = (count + 1) & 3;
		if count == 0 {
			out.extend_from_slice(&chunk.to_be_bytes()[1..]);
		}
	}
	Some(out)
}

/// Preserve 0.11.9's failure on invalid escapes and its treatment of
/// trailing whitespace and line endings. The 1.0 codec keeps invalid
/// escapes verbatim and removes whitespace at EOF instead.
pub(crate) fn quoted_printable_decode(bytes: &[u8]) -> Option<Vec<u8>> {
	// State machine adapted from mail-parser 0.11.9, Stalwart Labs LLC,
	// distributed under Apache-2.0 OR MIT.
	#[derive(Clone, Copy, PartialEq)]
	enum State {
		Text,
		Equals,
		Hex(u8),
	}
	let mut out = Vec::with_capacity(bytes.len());
	let mut state = State::Text;
	let mut whitespace = 0;
	let mut newline = b"\n".as_slice();
	for &byte in bytes {
		match byte {
			b'=' => {
				if state != State::Text {
					return None;
				}
				state = State::Equals;
			}
			b'\n' => {
				if state == State::Equals {
					state = State::Text;
				} else {
					out.truncate(out.len() - whitespace);
					out.extend_from_slice(newline);
				}
				whitespace = 0;
			}
			b'\r' => newline = b"\r\n",
			_ => match state {
				State::Text => {
					whitespace = if byte.is_ascii_whitespace() {
						whitespace + 1
					} else {
						0
					};
					out.push(byte);
				}
				State::Equals => {
					if let Some(hex) = hex(byte) {
						state = State::Hex(hex);
					} else if !byte.is_ascii_whitespace() {
						return None;
					}
				}
				State::Hex(high) => {
					out.push((high << 4) | hex(byte)?);
					state = State::Text;
					whitespace = 0;
				}
			},
		}
	}
	Some(out)
}

fn hex(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn charset_labels_keep_unknown_tokens_but_not_decoded_payload_damage() {
		for label in [
			"utf-16le",
			"utf-8",
			"x-unknown",
			"iso_8859-1:1987",
			"utf 16le",
			"utf\t16be",
			"utf-16\u{fffd}",
		] {
			assert!(is_charset_label(label), "{label:?}");
		}
		for label in ["", "\u{fffd}", "\u{fffd}\u{fffd}"] {
			assert!(!is_charset_label(label), "{label:?}");
		}
	}

	#[test]
	fn trust_names_fold_leaders_without_merging_distinct_names() {
		for name in [
			"Authentication-Results",
			":Authentication-Results",
			":: Authentication-Results",
		] {
			assert_eq!(trust_header_name(name), "Authentication-Results");
		}
		for name in ["X-Epistlefoo", "Authentication--Results", "X-Epistle\u{a0}"] {
			assert_eq!(trust_header_name(name), name);
		}
	}

	#[test]
	fn base64_keeps_the_old_success_and_failure_contract() {
		for (input, expected) in [
			(b"Zg".as_slice(), b"f".as_slice()),
			(b"Zm8", b"fo"),
			(b" Zm9v\r\n", b"foo"),
			(b"Zg====", b"f"),
			(b"Z", b""),
			(b"Zg\xffignored", b"f"),
		] {
			assert_eq!(base64_decode(input).as_deref(), Some(expected));
		}
		assert_eq!(base64_decode(b"Zm!9v"), None);
	}

	#[test]
	fn quoted_printable_keeps_failures_and_final_whitespace() {
		for (input, expected) in [
			(b"a=3Db=\r\nc".as_slice(), b"a=bc".as_slice()),
			(b"a \t\r\nb \t", b"a\r\nb \t"),
			(b"tail=", b"tail"),
			(b"tail=A", b"tail"),
		] {
			assert_eq!(quoted_printable_decode(input).as_deref(), Some(expected));
		}
		assert_eq!(quoted_printable_decode(b"a==b"), None);
		assert_eq!(quoted_printable_decode(b"a=XY"), None);
	}
}
