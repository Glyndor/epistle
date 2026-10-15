//! Images that carry more than a picture: an SVG with active content, and
//! a raster image with a program or an archive appended after its last
//! byte. Every check is one bounded pass over the decoded content.

use super::sniff::RealType;

/// How much of an SVG is read for active content.
pub const SVG_SCAN_BYTES: usize = 4 << 20;

/// Whether `content` is an SVG document: after a byte-order mark and
/// whitespace it starts with an XML prolog, or `<svg` appears in its first
/// KiB. Name and declared type play no part.
pub fn is_svg(content: &[u8]) -> bool {
	let content = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content);
	let start = content
		.iter()
		.take(1024)
		.position(|byte| !byte.is_ascii_whitespace())
		.unwrap_or(content.len());
	let head = &content[start..content.len().min(start + 1024)];
	starts_with_ignore_case(head, b"<?xml") || find_ignore_case(head, b"<svg").is_some()
}

/// Whether an SVG carries anything a viewer may run: a script element,
/// an `on...=` event attribute, a `javascript:` or `data:text/html` URL,
/// a `foreignObject`, or an embedded frame or object. Numeric character
/// references are decoded first and URL schemes are matched with
/// whitespace removed, as browsers read them. At most [`SVG_SCAN_BYTES`]
/// are read; a longer SVG counts as active, since its tail was not seen.
pub fn svg_is_active(content: &[u8]) -> bool {
	if content.len() > SVG_SCAN_BYTES {
		return true;
	}
	let text = decode_references(content);
	const ELEMENTS: &[&[u8]] = &[
		b"<script",
		b"<foreignobject",
		b"<iframe",
		b"<embed",
		b"<object",
	];
	if ELEMENTS
		.iter()
		.any(|element| find_ignore_case(&text, element).is_some())
	{
		return true;
	}
	if has_event_attribute(&text) {
		return true;
	}
	let compact: Vec<u8> = text
		.iter()
		.copied()
		.filter(|byte| !byte.is_ascii_whitespace())
		.collect();
	find_ignore_case(&compact, b"javascript:").is_some()
		|| find_ignore_case(&compact, b"data:text/html").is_some()
}

/// `&#NN;` and `&#xHH;` replaced by the byte they name when it is ASCII;
/// anything else is kept as written. One pass.
fn decode_references(content: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(content.len());
	let mut at = 0;
	while at < content.len() {
		if content[at] == b'&' && content.get(at + 1) == Some(&b'#') {
			let (hex, digits_at) = match content.get(at + 2) {
				Some(b'x' | b'X') => (true, at + 3),
				_ => (false, at + 2),
			};
			let digits = content[digits_at..]
				.iter()
				.take(8)
				.take_while(|byte| {
					if hex {
						byte.is_ascii_hexdigit()
					} else {
						byte.is_ascii_digit()
					}
				})
				.count();
			let value = std::str::from_utf8(&content[digits_at..digits_at + digits])
				.ok()
				.and_then(|text| u32::from_str_radix(text, if hex { 16 } else { 10 }).ok());
			if let Some(byte) = value
				.and_then(|value| u8::try_from(value).ok())
				.filter(u8::is_ascii)
				&& digits > 0
			{
				out.push(byte);
				at = digits_at + digits;
				if content.get(at) == Some(&b';') {
					at += 1;
				}
				continue;
			}
		}
		out.push(content[at]);
		at += 1;
	}
	out
}

/// An attribute named `on` plus letters, followed by `=`, after
/// whitespace, a slash or a quote: `onload=`, `ONCLICK =`.
fn has_event_attribute(text: &[u8]) -> bool {
	let mut at = 1;
	while at + 2 < text.len() {
		let before = text[at - 1];
		if (before.is_ascii_whitespace() || before == b'/' || before == b'"' || before == b'\'')
			&& text[at].eq_ignore_ascii_case(&b'o')
			&& text[at + 1].eq_ignore_ascii_case(&b'n')
		{
			let name_end = at
				+ 2 + text[at + 2..]
				.iter()
				.take_while(|byte| byte.is_ascii_alphabetic())
				.count();
			let after = text[name_end..]
				.iter()
				.find(|byte| !byte.is_ascii_whitespace());
			if name_end > at + 2 && after == Some(&b'=') {
				return true;
			}
			at = name_end.max(at + 1);
			continue;
		}
		at += 1;
	}
	false
}

/// Whether a raster image has a program, a script or a zip after its
/// logical end (PNG IEND, JPEG end of image, GIF trailer, WebP RIFF size).
/// An image whose end cannot be found is not judged here: the bytes are
/// then not the format the table says, and other rules apply.
pub fn has_appended_payload(real: RealType, content: &[u8]) -> bool {
	let end = match real {
		RealType::Png => png_end(content),
		RealType::Jpeg => jpeg_end(content),
		RealType::Gif => gif_end(content),
		RealType::Webp => webp_end(content),
		_ => None,
	};
	end.and_then(|end| content.get(end..))
		.is_some_and(contains_payload)
}

/// After the IEND chunk, walking the chunks by their lengths.
fn png_end(png: &[u8]) -> Option<usize> {
	let mut at = 8;
	loop {
		let len = u32::from_be_bytes(png.get(at..at + 4)?.try_into().ok()?) as usize;
		let kind = png.get(at + 4..at + 8)?;
		let next = at.checked_add(12)?.checked_add(len)?;
		if kind == b"IEND" {
			return Some(next.min(png.len()));
		}
		if next > png.len() {
			return None;
		}
		at = next;
	}
}

/// After the end-of-image marker that closes the first frame: segments are
/// walked by their lengths, entropy-coded data is scanned for markers.
fn jpeg_end(jpeg: &[u8]) -> Option<usize> {
	let mut at = 2;
	while at + 1 < jpeg.len() {
		if jpeg[at] != 0xff {
			return None;
		}
		let marker = jpeg[at + 1];
		match marker {
			0xd9 => return Some(at + 2),
			0xff => at += 1,
			0x01 | 0xd0..=0xd7 => at += 2,
			_ => {
				let len = usize::from(u16::from_be_bytes(
					jpeg.get(at + 2..at + 4)?.try_into().ok()?,
				));
				at = at.checked_add(2 + len)?;
				if marker == 0xda {
					// Entropy-coded data: the next marker is a 0xFF not
					// followed by 0x00 or a restart marker.
					while at + 1 < jpeg.len()
						&& !(jpeg[at] == 0xff
							&& jpeg[at + 1] != 0x00
							&& !(0xd0..=0xd7).contains(&jpeg[at + 1]))
					{
						at += 1;
					}
				}
			}
		}
	}
	None
}

/// After the trailer, walking image descriptors and extension sub-blocks.
fn gif_end(gif: &[u8]) -> Option<usize> {
	let flags = *gif.get(10)?;
	let mut at = 13;
	if flags & 0x80 != 0 {
		at += 3 << ((flags & 0x07) + 1);
	}
	loop {
		match *gif.get(at)? {
			0x3b => return Some(at + 1),
			0x21 => at = skip_sub_blocks(gif, at + 2)?,
			0x2c => {
				let local = *gif.get(at + 9)?;
				at += 10;
				if local & 0x80 != 0 {
					at += 3 << ((local & 0x07) + 1);
				}
				at = skip_sub_blocks(gif, at + 1)?;
			}
			_ => return None,
		}
	}
}

fn skip_sub_blocks(gif: &[u8], mut at: usize) -> Option<usize> {
	loop {
		let size = usize::from(*gif.get(at)?);
		at += 1;
		if size == 0 {
			return Some(at);
		}
		at = at.checked_add(size)?;
	}
}

/// Past the RIFF size, padded to an even length.
fn webp_end(webp: &[u8]) -> Option<usize> {
	let size = u32::from_le_bytes(webp.get(4..8)?.try_into().ok()?) as usize;
	let end = 8usize.checked_add(size)?.checked_add(size & 1)?;
	Some(end.min(webp.len()))
}

/// A PE (`MZ` whose header offset points at `PE\0\0`), ELF, a zip local
/// header or a `#!/` script anywhere in `tail`. One pass.
fn contains_payload(tail: &[u8]) -> bool {
	(0..tail.len()).any(|at| {
		let rest = &tail[at..];
		rest.starts_with(b"\x7fELF")
			|| rest.starts_with(b"PK\x03\x04")
			|| rest.starts_with(b"#!/")
			|| (rest.starts_with(b"MZ") && is_pe(rest))
	})
}

fn is_pe(mz: &[u8]) -> bool {
	let Some(offset) = mz.get(0x3c..0x40) else {
		return false;
	};
	let offset = u32::from_le_bytes([offset[0], offset[1], offset[2], offset[3]]) as usize;
	mz.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0")
}

fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
	text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Case-insensitive search for an ASCII `needle`; linear for the short
/// fixed needles used here.
fn find_ignore_case(text: &[u8], needle: &[u8]) -> Option<usize> {
	text.windows(needle.len())
		.position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
#[path = "image_tests.rs"]
pub(crate) mod tests;
