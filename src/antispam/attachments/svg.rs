//! SVG: an image format that is XML and can carry script. Telling script
//! apart from drawing by patterns is never complete, so an SVG attachment
//! is not inspected for content: being SVG is the finding. This module
//! only decides whether bytes are SVG, through every reading a viewer
//! might use.

use std::borrow::Cow;
use std::io::Read;

/// How far into a document an `svg` element is looked for.
pub const SVG_WINDOW: usize = 64 * 1024;

/// Decompressed bytes kept from a gzip-compressed SVG: enough to find the
/// element.
const GUNZIP_LIMIT: u64 = SVG_WINDOW as u64;

/// `content` as text: a UTF-8 byte-order mark removed, UTF-16 with a
/// byte-order mark decoded to UTF-8.
pub fn text_view(content: &[u8]) -> Cow<'_, [u8]> {
	if content.starts_with(b"\xff\xfe") {
		return Cow::Owned(utf16(&content[2..], true));
	}
	if content.starts_with(b"\xfe\xff") {
		return Cow::Owned(utf16(&content[2..], false));
	}
	Cow::Borrowed(content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content))
}

fn utf16(bytes: &[u8], little: bool) -> Vec<u8> {
	let units = bytes.as_chunks::<2>().0.iter().map(|&pair| {
		if little {
			u16::from_le_bytes(pair)
		} else {
			u16::from_be_bytes(pair)
		}
	});
	char::decode_utf16(units)
		.map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
		.collect::<String>()
		.into_bytes()
}

/// Whether `content` holds an `svg` element (`<svg` or `<prefix:svg`, any
/// case) in its first [`SVG_WINDOW`] bytes, read as UTF-8 and as UTF-16 in
/// either byte order, with or without a byte-order mark.
pub fn is_svg(content: &[u8]) -> bool {
	let window = &content[..content.len().min(SVG_WINDOW)];
	let body = window
		.strip_prefix(b"\xff\xfe")
		.or_else(|| window.strip_prefix(b"\xfe\xff"))
		.unwrap_or(window);
	has_svg_element(&text_view(window))
		|| has_svg_element(&utf16(body, true))
		|| has_svg_element(&utf16(body, false))
}

/// A gzip-compressed SVG (`.svgz`): the start of its decompressed bytes,
/// or `None` when it is not gzip or does not decompress at all.
pub fn gunzip(content: &[u8]) -> Option<Vec<u8>> {
	if !content.starts_with(b"\x1f\x8b") {
		return None;
	}
	let mut out = Vec::new();
	let _ = flate2::read::GzDecoder::new(content)
		.take(GUNZIP_LIMIT)
		.read_to_end(&mut out);
	(!out.is_empty()).then_some(out)
}

/// `<svg` or `<name:svg` followed by whitespace, `>` or `/`, any case.
/// One pass.
fn has_svg_element(text: &[u8]) -> bool {
	let mut at = 0;
	while let Some(offset) = text[at..].iter().position(|&byte| byte == b'<') {
		at += offset + 1;
		let name: Vec<u8> = text[at..]
			.iter()
			.take(64)
			.take_while(|byte| !byte.is_ascii_whitespace() && **byte != b'>' && **byte != b'/')
			.map(u8::to_ascii_lowercase)
			.collect();
		let local = name.rsplit(|&byte| byte == b':').next().unwrap_or(&name);
		if local == b"svg" {
			return true;
		}
	}
	false
}

/// The lower-case name of the first element, skipping `<?...?>`,
/// `<!...>` and comments, within [`SVG_WINDOW`].
pub(super) fn root_element(text: &[u8]) -> Option<String> {
	let window = &text[..text.len().min(SVG_WINDOW)];
	let mut at = 0;
	loop {
		at += window[at..].iter().position(|&byte| byte == b'<')?;
		let rest = &window[at..];
		if rest.starts_with(b"<!--") {
			at += 4 + rest[4..].windows(3).position(|w| w == b"-->")? + 3;
		} else if rest.starts_with(b"<?") || rest.starts_with(b"<!") {
			at += rest.iter().position(|&byte| byte == b'>')? + 1;
		} else {
			return Some(
				rest[1..]
					.iter()
					.take(64)
					.take_while(|byte| {
						!byte.is_ascii_whitespace() && **byte != b'>' && **byte != b'/'
					})
					.map(|byte| byte.to_ascii_lowercase() as char)
					.collect(),
			);
		}
	}
}

#[cfg(test)]
#[path = "svg_tests.rs"]
pub(crate) mod tests;
