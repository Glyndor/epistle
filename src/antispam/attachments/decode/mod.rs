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
	let mut failed = false;
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
		failed |= !decode_group(&clean, &mut out);
	}
	(out, segments > 1 || failed)
}

/// Decode alphabet-only base64 without padding, dropping a lone final
/// character that cannot form a byte. False when the group did not decode.
fn decode_group(clean: &[u8], out: &mut Vec<u8>) -> bool {
	use base64::Engine as _;
	use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
	const LENIENT: GeneralPurpose = GeneralPurpose::new(
		&base64::alphabet::STANDARD,
		GeneralPurposeConfig::new()
			.with_decode_allow_trailing_bits(true)
			.with_decode_padding_mode(DecodePaddingMode::Indifferent),
	);
	let usable = clean.len() - usize::from(clean.len() % 4 == 1);
	match LENIENT.decode(&clean[..usable]) {
		Ok(bytes) => {
			out.extend_from_slice(&bytes);
			true
		}
		Err(_) => false,
	}
}

/// Quoted-printable as clients read it: `=XX` in either case is a byte, a
/// `=` at the end of a line (trailing whitespace allowed) is a soft break,
/// and any other `=` is kept as it is. The second value says such an
/// invalid escape was seen, since clients do not agree on it.
pub fn quoted_printable(input: &[u8]) -> (Vec<u8>, bool) {
	let mut out = Vec::with_capacity(input.len());
	let mut invalid = false;
	let mut at = 0;
	while at < input.len() {
		let byte = input[at];
		at += 1;
		if byte != b'=' {
			out.push(byte);
			continue;
		}
		let rest = &input[at..];
		let blanks = rest
			.iter()
			.take_while(|&&byte| byte == b' ' || byte == b'\t')
			.count();
		let after = &rest[blanks..];
		if after.starts_with(b"\r\n") {
			at += blanks + 2;
		} else if after.starts_with(b"\n") {
			at += blanks + 1;
		} else if let (Some(high), Some(low)) = (
			rest.first().and_then(|&b| hex(b)),
			rest.get(1).and_then(|&b| hex(b)),
		) {
			out.push((high << 4) | low);
			at += 2;
		} else if after.is_empty() {
			at += blanks;
		} else {
			invalid = true;
			out.push(b'=');
		}
	}
	(out, invalid)
}

fn hex(byte: u8) -> Option<u8> {
	(byte as char).to_digit(16).map(|digit| digit as u8)
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

/// Find the uuencoded blocks in a text body, at most [`MAX_EMBEDDED`]; the
/// flag says more were left unread. One pass: a block's lines are consumed
/// by the block.
pub fn embedded_uuencode(text: &[u8]) -> (Vec<Embedded>, bool) {
	let mut found = Vec::new();
	let mut lines = text.split(|&byte| byte == b'\n');
	while let Some(line) = lines.next() {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		let Some(name) = begin_line(line) else {
			continue;
		};
		if found.len() == MAX_EMBEDDED {
			return (found, true);
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
	(found, false)
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
mod tests;
