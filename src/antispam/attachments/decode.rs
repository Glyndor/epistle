//! Transfer decoding as lenient as the clients that render the message, so
//! nothing a client would decode stays hidden from the scan.

/// Most uuencoded blocks taken from one text part.
pub const MAX_EMBEDDED: usize = 64;

/// Base64 the way mail clients read it: bytes outside the alphabet are
/// skipped, and data that continues after `=` padding (two encoded blocks
/// glued together) is decoded as a further block rather than dropped.
/// Returns the bytes and whether data followed padding, which two readers
/// may decode differently.
pub fn base64(input: &[u8]) -> (Vec<u8>, bool) {
	let mut out = Vec::with_capacity(input.len() / 4 * 3);
	let mut segments = 0;
	for segment in input.split(|&byte| byte == b'=') {
		let clean: Vec<u8> = segment
			.iter()
			.copied()
			.filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
			.collect();
		if clean.is_empty() {
			continue;
		}
		segments += 1;
		decode_group(&clean, &mut out);
	}
	(out, segments > 1)
}

/// Decode alphabet-only base64 without padding, dropping a lone final
/// character that cannot form a byte.
fn decode_group(clean: &[u8], out: &mut Vec<u8>) {
	use base64::Engine as _;
	use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
	const LENIENT: GeneralPurpose = GeneralPurpose::new(
		&base64::alphabet::STANDARD,
		GeneralPurposeConfig::new()
			.with_decode_allow_trailing_bits(true)
			.with_decode_padding_mode(DecodePaddingMode::Indifferent),
	);
	let usable = clean.len() - usize::from(clean.len() % 4 == 1);
	if let Ok(bytes) = LENIENT.decode(&clean[..usable]) {
		out.extend_from_slice(&bytes);
	}
}

/// Quoted-printable, falling back to the raw bytes when mail-parser
/// refuses the input.
pub fn quoted_printable(input: &[u8]) -> Vec<u8> {
	mail_parser::decoders::quoted_printable::quoted_printable_decode(input)
		.unwrap_or_else(|| input.to_vec())
}

/// The body of a uuencoded block, from the line after `begin` to `end`
/// (or the end of the input). Each line starts with its length character.
pub fn uuencode_lines<'a>(lines: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
	let mut out = Vec::new();
	for line in lines {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		if line == b"end" {
			break;
		}
		let Some((&count, data)) = line.split_first() else {
			continue;
		};
		let count = usize::from(count.wrapping_sub(b' ') & 0x3f);
		if count == 0 {
			continue;
		}
		let mut decoded = Vec::with_capacity(count + 2);
		for group in data.chunks(4) {
			let mut sextets = [0u8; 4];
			for (slot, &byte) in sextets.iter_mut().zip(group) {
				*slot = byte.wrapping_sub(b' ') & 0x3f;
			}
			decoded.push((sextets[0] << 2) | (sextets[1] >> 4));
			decoded.push((sextets[1] << 4) | (sextets[2] >> 2));
			decoded.push((sextets[2] << 6) | sextets[3]);
		}
		decoded.truncate(count);
		out.extend_from_slice(&decoded);
	}
	out
}

/// A whole uuencoded part: skip to the `begin` line when there is one.
pub fn uuencode(input: &[u8]) -> Vec<u8> {
	let mut lines = input.split(|&byte| byte == b'\n').peekable();
	if lines
		.peek()
		.is_some_and(|first| first.starts_with(b"begin "))
	{
		lines.next();
	}
	uuencode_lines(lines)
}

/// A uuencoded file pasted into a text body, which several clients show
/// as an attachment: its name and its decoded content.
#[derive(Debug, PartialEq, Eq)]
pub struct Embedded {
	/// The name on the `begin <mode> <name>` line.
	pub name: String,
	/// The decoded content.
	pub content: Vec<u8>,
}

/// Find the uuencoded blocks in a text body, at most [`MAX_EMBEDDED`]. One
/// pass: a block's lines are consumed by the block.
pub fn embedded_uuencode(text: &[u8]) -> Vec<Embedded> {
	let mut found = Vec::new();
	let mut lines = text.split(|&byte| byte == b'\n');
	while let Some(line) = lines.next() {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		let Some(name) = begin_line(line) else {
			continue;
		};
		if found.len() == MAX_EMBEDDED {
			break;
		}
		let body: Vec<&[u8]> = lines
			.by_ref()
			.take_while(|line| line.strip_suffix(b"\r").unwrap_or(line) != b"end")
			.collect();
		found.push(Embedded {
			name,
			content: uuencode_lines(body.into_iter()),
		});
	}
	found
}

/// `begin 644 name`: three or four octal digits, then the name.
fn begin_line(line: &[u8]) -> Option<String> {
	let rest = line.strip_prefix(b"begin ")?;
	let (mode, name) = rest.split_at(rest.iter().position(|&byte| byte == b' ')?);
	let name = name.get(1..)?;
	if !(3..=4).contains(&mode.len())
		|| !mode.iter().all(|byte| (b'0'..=b'7').contains(byte))
		|| name.is_empty()
	{
		return None;
	}
	Some(String::from_utf8_lossy(name).into_owned())
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
