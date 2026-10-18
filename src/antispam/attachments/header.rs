//! What one MIME header block declares, read the way the most permissive
//! mail client would read it.
//!
//! Clients disagree on duplicated headers and on which of several names to
//! show, and an attacker can aim the scanner at one reading while the
//! recipient's client uses another. So every candidate name is kept (both
//! `filename` and `name`, from every copy of the header, RFC 2231 and
//! RFC 2047 decoded by mail-parser), and anything two readers could see
//! differently marks the part ambiguous.

use mail_parser::{ContentType, HeaderName, MessageParser};

/// RFC 2046 section 5.1.1 caps a boundary at 70 characters. Clients accept
/// longer ones, so the walk does too, and marks the part ambiguous.
const RFC_BOUNDARY_LEN: usize = 70;

/// A boundary longer than a line could never be matched; past this the
/// declaration is ignored, and the part is ambiguous.
const MAX_BOUNDARY_LEN: usize = 998;

/// How a part's body is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
	/// 7bit, 8bit, binary or no header.
	Identity,
	/// Base64.
	Base64,
	/// Quoted-printable.
	QuotedPrintable,
	/// uuencode (`x-uuencode`, `uuencode`, `x-uue`).
	Uuencode,
}

/// What one header block declares.
#[derive(Debug)]
pub struct PartHeader {
	/// Every distinct candidate file name, in header order.
	pub names: Vec<String>,
	/// The declared `type/subtype`, lower case; `text/plain` when absent.
	/// The walk follows this one, the first, as clients do.
	pub declared_type: String,
	/// Every declared `type/subtype`, from every copy of the header, for
	/// the rules: any of them may be the one a client believes.
	pub declared_types: Vec<String>,
	/// The part is an attachment rather than message text.
	pub attachment: bool,
	/// The body's transfer encoding: the first one declared, as clients do.
	pub encoding: Encoding,
	/// The encodings the other copies of the header declare, when they
	/// differ from [`PartHeader::encoding`]: a client may use any of them.
	pub other_encodings: Vec<Encoding>,
	/// The multipart boundary, when the part is a usable multipart.
	pub boundary: Option<Vec<u8>>,
	/// Two readers could see this part differently.
	pub ambiguous: bool,
}

/// Parse one header block with mail-parser.
pub fn parse(block: &[u8]) -> PartHeader {
	let mut block = block.to_vec();
	block.extend_from_slice(b"\r\n");
	let parsed = MessageParser::new().parse_headers(&block);
	let headers = parsed
		.as_ref()
		.map(|message| message.headers())
		.unwrap_or(&[]);
	let mut types: Vec<&ContentType<'_>> = Vec::new();
	let mut dispositions: Vec<&ContentType<'_>> = Vec::new();
	let mut encodings: Vec<String> = Vec::new();
	// A Content-Type mail-parser could not read as a type: clients fall
	// back to text or to an opaque file, so the part is scanned as a file.
	let mut unparsed_type = false;
	for header in headers {
		match header.name {
			HeaderName::ContentType => match header.value.as_content_type() {
				Some(ct) => types.push(ct),
				None => unparsed_type = true,
			},
			HeaderName::ContentDisposition => dispositions.extend(header.value.as_content_type()),
			HeaderName::ContentTransferEncoding => encodings.extend(
				header
					.value
					.as_text()
					.map(|value| value.trim().to_ascii_lowercase()),
			),
			_ => {}
		}
	}
	// A block mail-parser cannot read at all is scanned as an opaque
	// attachment rather than skipped as text.
	let unreadable = parsed.is_none() && block.iter().any(|byte| !byte.is_ascii_whitespace());
	let mut ambiguous = unreadable
		|| unparsed_type
		|| types.len() > 1
		|| dispositions.len() > 1
		|| encodings.len() > 1;

	let type_name = |ct: &&ContentType<'_>| {
		match ct.subtype() {
			Some(subtype) => format!("{}/{}", ct.ctype(), subtype),
			None => ct.ctype().to_string(),
		}
		.to_ascii_lowercase()
	};
	let mut declared_types: Vec<String> = Vec::new();
	for name in types.iter().map(type_name) {
		if !declared_types.contains(&name) {
			declared_types.push(name);
		}
	}
	let declared_type = declared_types
		.first()
		.cloned()
		.unwrap_or_else(|| "text/plain".to_string());

	let mut names: Vec<String> = Vec::new();
	for (params, keys) in [
		(&dispositions, &["filename", "name"][..]),
		(&types, &["name", "filename"][..]),
	] {
		for ct in params.iter() {
			for attribute in ct.attributes().unwrap_or(&[]) {
				let key = attribute.name.trim_end_matches('*');
				if keys.iter().any(|wanted| key.eq_ignore_ascii_case(wanted))
					&& !attribute.value.is_empty()
					&& !names.iter().any(|seen| *seen == attribute.value)
				{
					names.push(attribute.value.to_string());
				}
			}
		}
	}
	ambiguous |= names_disagree(&names);

	// `Base64 `, `"base64"` and `base64; x=y` all reach some client as
	// base64; anything past case and outer whitespace is flagged.
	let encoding_token = |value: &str| {
		value
			.trim_matches('"')
			.split(|c: char| c == ';' || c.is_whitespace())
			.next()
			.unwrap_or("")
			.to_string()
	};
	let named = |token: &str| match token {
		"" | "7bit" | "8bit" | "binary" => Some(Encoding::Identity),
		"base64" => Some(Encoding::Base64),
		"quoted-printable" => Some(Encoding::QuotedPrintable),
		"x-uuencode" | "uuencode" | "x-uue" => Some(Encoding::Uuencode),
		_ => None,
	};
	let first = encodings.first().map(|value| {
		let token = encoding_token(value);
		ambiguous |= token != *value;
		token
	});
	let encoding = match first.as_deref() {
		None => Encoding::Identity,
		Some(token) => named(token).unwrap_or_else(|| {
			// An encoding nobody can name is read as-is, and flagged.
			ambiguous = true;
			Encoding::Identity
		}),
	};
	let mut other_encodings: Vec<Encoding> = Vec::new();
	for value in encodings.iter().skip(1) {
		if let Some(other) = named(&encoding_token(value))
			&& other != encoding
			&& !other_encodings.contains(&other)
		{
			other_encodings.push(other);
		}
	}

	let multipart = declared_type.starts_with("multipart/");
	let boundary = types
		.first()
		.filter(|_| multipart)
		.and_then(|ct| ct.attribute("boundary"))
		.filter(|value| !value.is_empty() && value.len() <= MAX_BOUNDARY_LEN)
		.map(|value| value.as_bytes().to_vec());
	if multipart && boundary.as_ref().is_none_or(|b| b.len() > RFC_BOUNDARY_LEN) {
		ambiguous = true;
	}
	if multipart
		&& types
			.iter()
			.filter_map(|ct| ct.attribute("boundary"))
			.count() > 1
	{
		ambiguous = true;
	}

	let disposition_attachment = dispositions
		.iter()
		.any(|cd| cd.ctype().eq_ignore_ascii_case("attachment"));
	// A multipart nobody can split is scanned as one opaque attachment.
	let attachment = unreadable
		|| unparsed_type
		|| !names.is_empty()
		|| disposition_attachment
		|| declared_types
			.iter()
			.any(|kind| !(kind.starts_with("text/") || kind.starts_with("multipart/")))
		|| (multipart && boundary.is_none());
	PartHeader {
		names,
		declared_type,
		declared_types,
		attachment,
		encoding,
		other_encodings,
		boundary,
		ambiguous,
	}
}

impl PartHeader {
	/// Whether a client could show this part as text, or open it as a message
	/// that holds some: a part that is not an attachment, a text part, a
	/// message or a multipart, a part with no type declared (RFC 2045 makes it
	/// `text/plain`), or a part whose headers two readers take differently.
	pub fn could_be_text(&self) -> bool {
		!self.attachment
			|| self.ambiguous
			|| self.declared_types.is_empty()
			|| self.declared_types.iter().any(|kind| {
				["text/", "message/", "multipart/"]
					.iter()
					.any(|prefix| kind.starts_with(prefix))
			})
	}
}

/// Candidate names whose extensions differ: one client may show `a.pdf`
/// and save `a.exe`.
fn names_disagree(names: &[String]) -> bool {
	let extension = |name: &str| {
		name.trim_end_matches(|c: char| c == '.' || c.is_whitespace())
			.rsplit_once('.')
			.map(|(_, ext)| ext.trim().to_lowercase())
	};
	names
		.windows(2)
		.any(|pair| extension(&pair[0]) != extension(&pair[1]))
}

#[cfg(test)]
#[path = "header_tests.rs"]
mod tests;
