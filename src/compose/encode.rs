//! Transfer encodings for leaf bodies (RFC 2045 section 6).

use base64::Engine;

use super::ComposeError;

/// Longest line RFC 5322 section 2.1.1 allows, without its CRLF.
const MAX_LINE: usize = 998;

/// Longest encoded line RFC 2045 allows for base64 and quoted-printable.
const ENCODED_LINE: usize = 76;

/// `bytes` with every line ending (CRLF, a bare LF or a bare CR) as CRLF.
pub(super) fn crlf(bytes: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 32);
	let mut index = 0;
	while index < bytes.len() {
		match bytes[index] {
			b'\r' => {
				out.extend_from_slice(b"\r\n");
				if bytes.get(index + 1) == Some(&b'\n') {
					index += 1;
				}
			}
			b'\n' => out.extend_from_slice(b"\r\n"),
			byte => out.push(byte),
		}
		index += 1;
	}
	out
}

/// A text body: `7bit` when every byte is printable ASCII (or a tab) and
/// no line is longer than 998 octets, quoted-printable otherwise.
pub(super) fn text(text: &str) -> (&'static str, Vec<u8>) {
	let normalised = crlf(text.as_bytes());
	let plain = lines_fit(&normalised)
		&& normalised
			.iter()
			.all(|&b| b == b'\t' || b == b'\r' || b == b'\n' || (0x20..0x7f).contains(&b));
	if plain {
		return ("7bit", normalised);
	}
	("quoted-printable", quoted_printable(&normalised))
}

/// Quoted-printable (RFC 2045 section 6.7) of CRLF-normalised text: hard
/// line breaks kept, soft breaks so no encoded line passes 76 characters,
/// and a space or tab before a line break encoded.
pub(super) fn quoted_printable(normalised: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(normalised.len() + normalised.len() / 2);
	for (index, line) in normalised.split(|&b| b == b'\n').enumerate() {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		if index > 0 {
			out.extend_from_slice(b"\r\n");
		}
		let mut column = 0;
		for (position, &byte) in line.iter().enumerate() {
			let last = position + 1 == line.len();
			let literal = match byte {
				b' ' | b'\t' => !last,
				b'=' => false,
				0x21..=0x7e => true,
				_ => false,
			};
			let width = if literal { 1 } else { 3 };
			// Keep room for the `=` of a soft break.
			let room = if last { ENCODED_LINE } else { ENCODED_LINE - 1 };
			if column + width > room {
				out.extend_from_slice(b"=\r\n");
				column = 0;
			}
			if literal {
				out.push(byte);
			} else {
				out.extend_from_slice(format!("={byte:02X}").as_bytes());
			}
			column += width;
		}
	}
	out
}

/// Base64 in lines of 76 characters joined by CRLF.
pub(super) fn base64_lines(bytes: &[u8]) -> Vec<u8> {
	let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
	let mut out = Vec::with_capacity(encoded.len() + encoded.len() / ENCODED_LINE * 2);
	for (index, chunk) in encoded.as_bytes().chunks(ENCODED_LINE).enumerate() {
		if index > 0 {
			out.extend_from_slice(b"\r\n");
		}
		out.extend_from_slice(chunk);
	}
	out
}

/// An attached message, which RFC 2046 section 5.2.1 does not allow in
/// base64: `7bit` when it is ASCII, `8bit` otherwise, with CRLF line
/// endings. A line over 998 octets fits neither and is refused.
pub(super) fn message(bytes: &[u8]) -> Result<(&'static str, Vec<u8>), ComposeError> {
	let normalised = crlf(bytes);
	if !lines_fit(&normalised) {
		return Err(ComposeError::LongLine);
	}
	let encoding = if normalised.is_ascii() {
		"7bit"
	} else {
		"8bit"
	};
	Ok((encoding, normalised))
}

/// True when no line of CRLF-normalised `bytes` is longer than 998 octets.
fn lines_fit(normalised: &[u8]) -> bool {
	normalised
		.split(|&b| b == b'\n')
		.all(|line| line.strip_suffix(b"\r").unwrap_or(line).len() <= MAX_LINE)
}
