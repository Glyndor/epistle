//! Building outgoing MIME messages (RFC 2045-2049) from parts.
//!
//! `POST /api/v1/send` and JMAP `Email/set` both write new messages: a text
//! and/or an HTML body, inline parts referenced by `cid:`, and attachments.
//! They share this builder so the structure, the transfer encodings, the
//! header folding and the RFC 2231 file names come out the same way from
//! both. The callers validate their own input; the builder still refuses a
//! line break in any header-bound value, so nothing it writes can carry an
//! injected header.

mod encode;
mod header;
mod sniff;

pub use header::{address_list, structured, unstructured};
pub use sniff::content_type_for;

/// How a leaf part is shown: as an attachment, or inline in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
	/// `Content-Disposition: attachment`.
	Attachment,
	/// `Content-Disposition: inline`.
	Inline,
}

/// The content of a leaf part.
#[derive(Debug, Clone)]
pub enum Content {
	/// Text written as UTF-8 (`charset=utf-8`), line endings normalised to
	/// CRLF, `7bit` when it allows it and quoted-printable otherwise.
	Text(String),
	/// Octets written as base64, except an attached message
	/// (`message/rfc822`), which RFC 2046 section 5.2.1 keeps in `7bit` or
	/// `8bit`.
	Bytes(Vec<u8>),
}

/// One non-multipart part.
#[derive(Debug, Clone)]
pub struct Leaf {
	/// `type/subtype`, without parameters.
	pub content_type: String,
	/// What the part holds.
	pub content: Content,
	/// `Content-Disposition`, when the part has one.
	pub disposition: Option<Disposition>,
	/// File name, written as `filename` (and `name`) parameters.
	pub name: Option<String>,
	/// Content-ID without the angle brackets, for `cid:` references.
	pub content_id: Option<String>,
}

impl Leaf {
	/// A `text/<subtype>` body part.
	pub fn text(subtype: &str, text: &str) -> Self {
		Leaf {
			content_type: format!("text/{subtype}"),
			content: Content::Text(text.to_string()),
			disposition: None,
			name: None,
			content_id: None,
		}
	}
}

/// A part: a leaf or a multipart holding further parts.
#[derive(Debug, Clone)]
pub enum Part {
	/// A part with content.
	Leaf(Leaf),
	/// `multipart/<subtype>` around `parts`.
	Multipart {
		/// `mixed`, `alternative`, `related`, ...
		subtype: String,
		/// The parts, in order.
		parts: Vec<Part>,
	},
}

/// The bodies of a message before they are given a structure.
#[derive(Debug, Default)]
pub struct Bodies {
	/// The `text/plain` body.
	pub text: Option<Leaf>,
	/// The `text/html` body.
	pub html: Option<Leaf>,
	/// Parts the HTML body refers to by `cid:`.
	pub inline: Vec<Leaf>,
	/// Attachments, after the body.
	pub attachments: Vec<Leaf>,
}

impl Bodies {
	/// The usual structure: `multipart/mixed` around the body and the
	/// attachments; the body a `multipart/alternative` of text then HTML;
	/// the HTML a `multipart/related` with its inline parts. A level with a
	/// single part is that part. Inline parts with no HTML to refer to them
	/// are attached. No body at all is an empty text part.
	pub fn assemble(self) -> Part {
		let mut attachments: Vec<Part> = Vec::new();
		let html = match self.html {
			Some(html) if !self.inline.is_empty() => {
				let mut parts = vec![Part::Leaf(html)];
				parts.extend(self.inline.into_iter().map(Part::Leaf));
				Some(multipart("related", parts))
			}
			Some(html) => Some(Part::Leaf(html)),
			None => {
				attachments.extend(self.inline.into_iter().map(Part::Leaf));
				None
			}
		};
		let body = match (self.text, html) {
			(Some(text), Some(html)) => multipart("alternative", vec![Part::Leaf(text), html]),
			(Some(text), None) => Part::Leaf(text),
			(None, Some(html)) => html,
			(None, None) => Part::Leaf(Leaf::text("plain", "")),
		};
		attachments.extend(self.attachments.into_iter().map(Part::Leaf));
		if attachments.is_empty() {
			return body;
		}
		let mut parts = vec![body];
		parts.extend(attachments);
		multipart("mixed", parts)
	}
}

/// A `multipart/<subtype>` of `parts`.
pub fn multipart(subtype: &str, parts: Vec<Part>) -> Part {
	Part::Multipart {
		subtype: subtype.to_string(),
		parts,
	}
}

/// Why a part could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComposeError {
	/// A header value or parameter would end its line early.
	#[error("a header value contains a line break or a control character")]
	HeaderBreak,
	/// A content type that is not `type/subtype`, or a multipart leaf.
	#[error("invalid content type {0:?}")]
	ContentType(String),
	/// A Content-ID with a space, a bracket or a control character.
	#[error("invalid content id")]
	ContentId,
	/// An attached message that cannot be written without base64.
	#[error("an attached message has a line longer than 998 octets")]
	LongLine,
	/// More than 16 levels of multipart nesting.
	#[error("the MIME structure is nested too deeply")]
	TooDeep,
}

/// Deepest multipart nesting the builder writes.
const MAX_DEPTH: usize = 16;

/// The message: `headers` (whole lines from [`unstructured`],
/// [`structured`] and [`address_list`]), `MIME-Version`, then `root`.
pub fn write(headers: &[String], root: &Part) -> Result<Vec<u8>, ComposeError> {
	let mut out = Vec::new();
	for line in headers {
		out.extend_from_slice(line.as_bytes());
	}
	out.extend_from_slice(b"MIME-Version: 1.0\r\n");
	write_part(&mut out, root, 0)?;
	if matches!(root, Part::Multipart { .. }) {
		out.extend_from_slice(b"\r\n");
	}
	Ok(out)
}

/// One part: its `Content-*` headers, a blank line and its body, with no
/// line break after the body (the next delimiter starts with one).
fn write_part(out: &mut Vec<u8>, part: &Part, depth: usize) -> Result<(), ComposeError> {
	if depth > MAX_DEPTH {
		return Err(ComposeError::TooDeep);
	}
	match part {
		Part::Leaf(leaf) => write_leaf(out, leaf),
		Part::Multipart { subtype, parts } => {
			if !header::is_token(subtype) {
				return Err(ComposeError::ContentType(format!("multipart/{subtype}")));
			}
			// `=_` cannot occur in base64 or quoted-printable output.
			let boundary = format!("=_{}", uuid::Uuid::new_v4().simple());
			out.extend_from_slice(
				format!(
					"Content-Type: multipart/{};\r\n boundary=\"{boundary}\"\r\n\r\n",
					subtype.to_ascii_lowercase()
				)
				.as_bytes(),
			);
			for (index, part) in parts.iter().enumerate() {
				let delimiter = if index == 0 { "" } else { "\r\n" };
				out.extend_from_slice(format!("{delimiter}--{boundary}\r\n").as_bytes());
				write_part(out, part, depth + 1)?;
			}
			out.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
			Ok(())
		}
	}
}

fn write_leaf(out: &mut Vec<u8>, leaf: &Leaf) -> Result<(), ComposeError> {
	let content_type = header::leaf_content_type(&leaf.content_type)?;
	let (encoding, body) = match &leaf.content {
		Content::Text(text) => encode::text(text),
		Content::Bytes(bytes) if content_type == "message/rfc822" => encode::message(bytes)?,
		Content::Bytes(bytes) => ("base64", encode::base64_lines(bytes)),
	};
	let mut head = format!("Content-Type: {content_type}");
	if matches!(leaf.content, Content::Text(_)) {
		head.push_str("; charset=utf-8");
	}
	if let Some(name) = &leaf.name {
		head.push_str(&header::param("name", name)?);
	}
	head.push_str(&format!("\r\nContent-Transfer-Encoding: {encoding}\r\n"));
	if let Some(disposition) = leaf.disposition {
		head.push_str(match disposition {
			Disposition::Attachment => "Content-Disposition: attachment",
			Disposition::Inline => "Content-Disposition: inline",
		});
		if let Some(name) = &leaf.name {
			head.push_str(&header::param("filename", name)?);
		}
		head.push_str("\r\n");
	}
	if let Some(id) = &leaf.content_id {
		if !header::is_content_id(id) {
			return Err(ComposeError::ContentId);
		}
		head.push_str(&format!("Content-ID: <{id}>\r\n"));
	}
	head.push_str("\r\n");
	out.extend_from_slice(head.as_bytes());
	out.extend_from_slice(&body);
	Ok(())
}

#[cfg(test)]
#[path = "compose_tests.rs"]
mod tests;
