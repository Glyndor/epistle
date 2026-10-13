//! TXT value encoding shared by every DNS provider.
//!
//! A TXT value exists in three shapes, and each provider API wants one of
//! them on the way in and hands back one of them on the way out:
//!
//! - **logical**: the text a resolver returns after concatenating the
//!   record's character-strings with nothing in between (RFC 7208 §3.3 for
//!   SPF, RFC 6376 §3.6.2.2 for DKIM). This is what callers put in
//!   [`DnsRecord::value`](crate::dns::provider::DnsRecord::value) and what
//!   every provider's `list` returns, so values compare equal whichever
//!   provider stored them.
//! - **character-strings**: the logical value cut into pieces of at most
//!   255 octets (RFC 1035 §3.3.14), for an API that takes them as an array
//!   or for the DNS wire format itself.
//! - **presentation**: each piece in double quotes with `"` and `\`
//!   backslash-escaped and any octet outside printable ASCII as a numeric
//!   escape, pieces separated by one space (RFC 1035 §5.1), the way a zone
//!   file writes it.
//!
//! [`txt_logical`] reads any of the three back to the logical value. It is
//! deliberately tolerant: a caller that already wrapped its value in quotes,
//! or a provider that answers in presentation form, both read back to the
//! same text, so writing a value twice never doubles its quotes and reading
//! a published record never reports a change that is only in the quoting.

/// RFC 1035 §3.3.14 caps one character-string at 255 octets.
const MAX_STRING: usize = 255;

/// What a provider API expects in the value field of a TXT record, and
/// hands back when it lists one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtForm {
	/// The logical value, unquoted and unsplit. The provider adds the quotes
	/// and cuts the 255-octet pieces itself.
	Logical,
	/// The RFC 1035 presentation form: quoted, `"` and `\` escaped, an octet
	/// outside printable ASCII as `\DDD` in decimal, cut into 255-octet
	/// pieces separated by one space (see [`txt_presentation`]).
	Presentation,
	/// The same presentation form with the numeric escape in octal
	/// (`\NNN`), which is what Route 53 reads and writes instead of the RFC
	/// 1035 decimal.
	PresentationOctal,
}

/// The logical value of `value`, whichever shape it arrives in.
///
/// Surrounding whitespace is trimmed. When the trimmed value is a sequence
/// of one or more double-quoted strings separated by optional whitespace
/// (the presentation form, or a caller that wrapped its value in quotes),
/// the strings are unescaped (`\X` is `X`, `\DDD` is the octet with that
/// decimal value) and concatenated with nothing in between. Anything else,
/// including text with an unbalanced quote or with bytes outside the quoted
/// strings, is taken as already logical and returned trimmed but otherwise
/// untouched.
pub fn txt_logical(value: &str) -> String {
	txt_decode(value, TxtForm::Presentation)
}

/// The logical value of `value` as a provider that uses `form` returns it.
/// Identical to [`txt_logical`] except that for
/// [`TxtForm::PresentationOctal`] a three-digit numeric escape is read in
/// octal.
pub fn txt_decode(value: &str, form: TxtForm) -> String {
	let trimmed = value.trim();
	if !trimmed.starts_with('"') {
		return trimmed.to_string();
	}
	let radix = if form == TxtForm::PresentationOctal {
		8
	} else {
		10
	};
	match unquote(trimmed.as_bytes(), radix) {
		Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
		None => trimmed.to_string(),
	}
}

/// Parse a run of quoted character-strings, or `None` when `input` is not
/// one (an unterminated string, a bad numeric escape, or text between
/// strings). `radix` is 10 for RFC 1035 `\DDD` and 8 for Route 53.
fn unquote(input: &[u8], radix: u32) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(input.len());
	let mut i = 0;
	while i < input.len() {
		if input[i] != b'"' {
			return None;
		}
		i += 1;
		loop {
			match *input.get(i)? {
				b'"' => {
					i += 1;
					break;
				}
				b'\\' => {
					let next = *input.get(i + 1)?;
					if next.is_ascii_digit() {
						let digits = input.get(i + 1..i + 4)?;
						let n = digits.iter().try_fold(0u32, |acc, d| {
							char::from(*d).to_digit(radix).map(|v| acc * radix + v)
						})?;
						out.push(u8::try_from(n).ok()?);
						i += 4;
					} else {
						out.push(next);
						i += 2;
					}
				}
				byte => {
					out.push(byte);
					i += 1;
				}
			}
		}
		while input.get(i).is_some_and(u8::is_ascii_whitespace) {
			i += 1;
		}
	}
	Some(out)
}

/// The logical value of `value` cut into character-strings of at most 255
/// octets, never inside a multi-byte UTF-8 character. A value that fits is
/// one string; an empty value is one empty string.
pub fn txt_character_strings(value: &str) -> Vec<String> {
	let logical = txt_logical(value);
	if logical.len() <= MAX_STRING {
		return vec![logical];
	}
	let mut out = Vec::new();
	let mut start = 0;
	while start < logical.len() {
		let mut end = (start + MAX_STRING).min(logical.len());
		while end < logical.len() && !logical.is_char_boundary(end) {
			end -= 1;
		}
		out.push(logical[start..end].to_string());
		start = end;
	}
	out
}

/// The presentation form of `value`: its logical value cut into
/// character-strings, each wrapped in double quotes with `"` and `\`
/// backslash-escaped and any octet outside printable ASCII (space
/// included as printable) written `\DDD` in decimal, joined by one space.
/// The escaping is applied per piece after the cut, so the 255-octet limit
/// counts logical octets and an escape never straddles two pieces.
pub fn txt_presentation(value: &str) -> String {
	presentation(value, 10)
}

fn presentation(value: &str, radix: u32) -> String {
	txt_character_strings(value)
		.iter()
		.map(|piece| {
			let mut out = String::with_capacity(piece.len() + 2);
			out.push('"');
			for byte in piece.bytes() {
				match byte {
					b'"' | b'\\' => {
						out.push('\\');
						out.push(char::from(byte));
					}
					b' '..=b'~' => out.push(char::from(byte)),
					_ if radix == 8 => out.push_str(&format!("\\{byte:03o}")),
					_ => out.push_str(&format!("\\{byte:03}")),
				}
			}
			out.push('"');
			out
		})
		.collect::<Vec<_>>()
		.join(" ")
}

/// `value` encoded the way a provider that takes `form` expects it.
pub fn txt_encode(value: &str, form: TxtForm) -> String {
	match form {
		TxtForm::Logical => txt_logical(value),
		TxtForm::Presentation => presentation(value, 10),
		TxtForm::PresentationOctal => presentation(value, 8),
	}
}

/// Whether two TXT values carry the same logical text, whatever shape each
/// is in. This is the change test: a published record whose listed value
/// matches the expected one this way needs no write.
pub fn same_txt_value(a: &str, b: &str) -> bool {
	txt_logical(a) == txt_logical(b)
}

#[cfg(test)]
#[path = "txt_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "txt_fixtures.rs"]
pub(crate) mod fixtures;
