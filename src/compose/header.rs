//! Header lines and MIME parameters for the builder: RFC 2047 encoded-words
//! for text outside ASCII, folding at 78 characters where a value has room
//! to fold, and RFC 2231 parameters for file names.

use super::ComposeError;

/// Line length RFC 5322 section 2.1.1 asks a writer to fold at.
const FOLD_AT: usize = 78;

/// Longest parameter value written as a quoted string.
const QUOTED: usize = 60;

/// Longest RFC 2231 segment of an encoded parameter value, so that
/// ` filename*NN*=utf-8''` and the segment stay within 78 characters.
const SEGMENT: usize = 48;

/// True when `value` holds a CR, an LF or another control character other
/// than a tab: what would end the header line early.
fn breaks(value: &str) -> bool {
	value.chars().any(|c| c.is_control() && c != '\t')
}

/// An unstructured field (`Subject`, `X-*`): written as is when it is
/// printable ASCII, folded at its spaces; RFC 2047 encoded-words otherwise.
pub fn unstructured(name: &str, value: &str) -> Result<String, ComposeError> {
	if breaks(value) {
		return Err(ComposeError::HeaderBreak);
	}
	if value.is_ascii() {
		return Ok(fold(name, value));
	}
	Ok(format!(
		"{name}: {}\r\n",
		crate::util::encoded_word::encode(value)
	))
}

/// A structured field whose value the caller already built from ASCII
/// tokens (message ids, URLs, keywords), folded at its spaces.
pub fn structured(name: &str, value: &str) -> Result<String, ComposeError> {
	if breaks(value) || !value.is_ascii() {
		return Err(ComposeError::HeaderBreak);
	}
	Ok(fold(name, value))
}

/// An address list (`To`, `Cc`, `Reply-To`), folded between addresses. An
/// address may arrive already folded (CRLF and a space, as long RFC 2047
/// names are): it is unfolded first, since a fold cannot start a new
/// header line; any other line break is refused.
pub fn address_list(name: &str, addresses: &[String]) -> Result<String, ComposeError> {
	let joined = addresses
		.join(", ")
		.replace("\r\n ", " ")
		.replace("\r\n\t", " ");
	if breaks(&joined) {
		return Err(ComposeError::HeaderBreak);
	}
	Ok(fold(name, &joined))
}

/// `Name: value` with a fold (CRLF and the space it replaces) before a
/// word that would carry the line past 78 characters.
fn fold(name: &str, value: &str) -> String {
	let mut out = format!("{name}:");
	let mut column = out.len();
	for word in value.split(' ') {
		if column + 1 + word.len() > FOLD_AT && column > name.len() + 1 {
			out.push_str("\r\n");
			column = 0;
		}
		out.push(' ');
		out.push_str(word);
		column += 1 + word.len();
	}
	out.push_str("\r\n");
	out
}

/// An RFC 2045 token: the characters a MIME type or subtype may use.
pub(super) fn is_token(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 127
		&& value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

/// The lowercase `type/subtype` of a leaf. A leaf is never multipart: the
/// structure is the builder's to write.
pub(super) fn leaf_content_type(value: &str) -> Result<String, ComposeError> {
	let lower = value.to_ascii_lowercase();
	match lower.split_once('/') {
		// RFC 2046 section 5.2.2 and 5.2.3: these two may only be 7bit,
		// which arbitrary octets cannot be.
		Some(("message", "partial" | "external-body")) => {
			Err(ComposeError::ContentType(value.to_string()))
		}
		Some((kind, subtype)) if is_token(kind) && is_token(subtype) && kind != "multipart" => {
			Ok(lower)
		}
		_ => Err(ComposeError::ContentType(value.to_string())),
	}
}

/// A Content-ID without its angle brackets: printable ASCII with no space
/// and no bracket, at most 250 characters.
pub(super) fn is_content_id(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 250
		&& value
			.bytes()
			.all(|b| (0x21..0x7f).contains(&b) && b != b'<' && b != b'>')
}

/// `;` and a folded parameter: `name="value"` for short printable ASCII,
/// otherwise RFC 2231 `name*=utf-8''...`, split into numbered segments
/// (`name*0*`, `name*1*`, ...) when long.
pub(super) fn param(name: &str, value: &str) -> Result<String, ComposeError> {
	if breaks(value) {
		return Err(ComposeError::HeaderBreak);
	}
	let quotable = value.len() <= QUOTED
		&& value
			.bytes()
			.all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\');
	if quotable {
		return Ok(format!(";\r\n {name}=\"{value}\""));
	}
	let mut segments: Vec<String> = vec![String::new()];
	for byte in value.bytes() {
		let piece = if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
			(byte as char).to_string()
		} else {
			format!("%{byte:02X}")
		};
		if segments
			.last()
			.is_some_and(|s| s.len() + piece.len() > SEGMENT)
		{
			segments.push(String::new());
		}
		if let Some(last) = segments.last_mut() {
			last.push_str(&piece);
		}
	}
	if segments.len() == 1 {
		return Ok(format!(";\r\n {name}*=utf-8''{}", segments[0]));
	}
	let mut out = String::new();
	for (index, segment) in segments.iter().enumerate() {
		let charset = if index == 0 { "utf-8''" } else { "" };
		out.push_str(&format!(";\r\n {name}*{index}*={charset}{segment}"));
	}
	Ok(out)
}
