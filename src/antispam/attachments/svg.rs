//! SVG: an image format that is XML and can carry script. Recognised by
//! its root element, read through UTF-16 and gzip, and judged active when
//! anything in it could run in a viewer.

use std::borrow::Cow;
use std::io::Read;

/// How much of an SVG is read for active content, after decompression.
pub const SVG_SCAN_BYTES: usize = 4 << 20;

/// How far into a document the root element is looked for: prologs,
/// doctypes and comments may come first.
const ROOT_WINDOW: usize = 64 * 1024;

/// What an SVG holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvgVerdict {
	/// Nothing that runs.
	Clean,
	/// Script, an event handler, a script URL or an embedded document.
	Active,
	/// It cannot be read cleanly: internal entity declarations, which can
	/// expand to anything, or gzip that does not decompress.
	Ambiguous,
}

/// `content` as text: a UTF-8 byte-order mark removed, UTF-16 with a
/// byte-order mark decoded to UTF-8. At most [`SVG_SCAN_BYTES`] plus one
/// byte is produced from UTF-16, enough to tell an over-long document.
pub fn text_view(content: &[u8]) -> Cow<'_, [u8]> {
	let little = content.starts_with(b"\xff\xfe");
	if !little && !content.starts_with(b"\xfe\xff") {
		return Cow::Borrowed(content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content));
	}
	let units = content[2..].as_chunks::<2>().0.iter().map(|&pair| {
		if little {
			u16::from_le_bytes(pair)
		} else {
			u16::from_be_bytes(pair)
		}
	});
	let mut out = Vec::new();
	for c in char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)) {
		if out.len() > SVG_SCAN_BYTES {
			break;
		}
		let mut buffer = [0; 4];
		out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
	}
	Cow::Owned(out)
}

/// Whether `content` is an SVG document: its root element, after any
/// prolog, doctype and comments, is `svg` or `prefix:svg`.
pub fn is_svg(content: &[u8]) -> bool {
	root_element(&text_view(content)).is_some_and(|name| name == "svg" || name.ends_with(":svg"))
}

/// The lower-case name of the first element, skipping `<?...?>`,
/// `<!...>` and comments, within [`ROOT_WINDOW`].
pub(super) fn root_element(text: &[u8]) -> Option<String> {
	let window = &text[..text.len().min(ROOT_WINDOW)];
	let mut at = 0;
	loop {
		at += window[at..].iter().position(|&byte| byte == b'<')?;
		let rest = &window[at..];
		if rest.starts_with(b"<!--") {
			at += 4 + find(&rest[4..], b"-->")? + 3;
		} else if rest.starts_with(b"<?") || rest.starts_with(b"<!") {
			at += rest.iter().position(|&byte| byte == b'>')? + 1;
		} else {
			return Some(tag_name(&rest[1..]));
		}
	}
}

fn tag_name(after_bracket: &[u8]) -> String {
	after_bracket
		.iter()
		.take(64)
		.take_while(|byte| !byte.is_ascii_whitespace() && **byte != b'>' && **byte != b'/')
		.map(|byte| byte.to_ascii_lowercase() as char)
		.collect()
}

/// Gzip-compressed SVG (`.svgz`) decompressed, at most [`SVG_SCAN_BYTES`]
/// plus one byte; `None` when it is not gzip or does not decompress.
pub fn gunzip(content: &[u8]) -> Option<Vec<u8>> {
	if !content.starts_with(b"\x1f\x8b") {
		return None;
	}
	let mut out = Vec::new();
	flate2::read::GzDecoder::new(content)
		.take(SVG_SCAN_BYTES as u64 + 1)
		.read_to_end(&mut out)
		.ok()?;
	Some(out)
}

/// Judge an SVG. A document longer than [`SVG_SCAN_BYTES`] is active, as
/// its tail was not read.
pub fn inspect_svg(content: &[u8]) -> SvgVerdict {
	let text = text_view(content);
	if text.len() > SVG_SCAN_BYTES {
		return SvgVerdict::Active;
	}
	if find_ignore_case(&text, b"<!entity").is_some() {
		return SvgVerdict::Ambiguous;
	}
	let text = decode_references(&text);
	if has_active_element(&text) || has_event_attribute(&text) {
		return SvgVerdict::Active;
	}
	let compact: Vec<u8> = text
		.iter()
		.copied()
		.filter(|byte| !byte.is_ascii_whitespace())
		.collect();
	let schemes: [&[u8]; 3] = [b"javascript:", b"vbscript:", b"data:text/html"];
	if schemes
		.iter()
		.any(|scheme| find_ignore_case(&compact, scheme).is_some())
	{
		return SvgVerdict::Active;
	}
	SvgVerdict::Clean
}

/// An element whose local name (after any `prefix:`) runs or embeds
/// content.
fn has_active_element(text: &[u8]) -> bool {
	const ACTIVE: &[&str] = &[
		"script",
		"foreignobject",
		"iframe",
		"embed",
		"object",
		"handler",
	];
	let mut at = 0;
	while let Some(offset) = text[at..].iter().position(|&byte| byte == b'<') {
		at += offset + 1;
		let name = tag_name(&text[at..]);
		let local = name.rsplit(':').next().unwrap_or(&name);
		if ACTIVE.contains(&local) {
			return true;
		}
	}
	false
}

/// `&#NN;` and `&#xHH;` replaced by the byte they name when it is ASCII,
/// and the HTML names browsers accept inside inline SVG for the characters
/// that build a script URL (`&colon;`, `&Tab;`, `&NewLine;`). One pass.
fn decode_references(content: &[u8]) -> Vec<u8> {
	const NAMED: &[(&[u8], u8)] = &[(b"&colon;", b':'), (b"&tab;", b'\t'), (b"&newline;", b'\n')];
	let mut out = Vec::with_capacity(content.len());
	let mut at = 0;
	while at < content.len() {
		if content[at] == b'&' {
			if let Some((name, byte)) = NAMED.iter().find(|(name, _)| {
				content.len() >= at + name.len()
					&& content[at..at + name.len()].eq_ignore_ascii_case(name)
			}) {
				out.push(*byte);
				at += name.len();
				continue;
			}
			if content.get(at + 1) == Some(&b'#') {
				let (hex, digits_at) = match content.get(at + 2) {
					Some(b'x' | b'X') => (true, at + 3),
					_ => (false, at + 2),
				};
				let digits = content[digits_at.min(content.len())..]
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

fn find(text: &[u8], needle: &[u8]) -> Option<usize> {
	text.windows(needle.len())
		.position(|window| window == needle)
}

/// Case-insensitive search for a short ASCII `needle`.
pub(super) fn find_ignore_case(text: &[u8], needle: &[u8]) -> Option<usize> {
	text.windows(needle.len())
		.position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
#[path = "svg_tests.rs"]
pub(crate) mod tests;
