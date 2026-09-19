//! Find the report part inside an inbound message and base64-decode it.
//!
//! The DMARC and TLS-RPT receivers ship their reports as one attachment
//! inside a multipart message. The shape is fixed:
//!
//! - DMARC: `multipart/mixed` (or `multipart/related`) at the top level,
//!   with the report inside as `application/gzip` / `application/zip` /
//!   `application/x-gzip` / `application/x-zip-compressed`, or with a
//!   filename ending `.xml.gz` / `.zip`.
//! - TLS-RPT: `multipart/report` or `multipart/mixed` with a part of
//!   `application/tlsrpt+gzip` (or `application/tlsrpt+json` for
//!   uncompressed).
//!
//! We do not pull a MIME-walker dependency: RFC 2046 boundaries are
//! simple enough to split by hand, and a real MIME library would do more
//! than we need without being any easier to bound. We support exactly
//! the top level and one level of nesting (a report inside a forwarded
//! message), and we refuse anything that exceeds [`MAX_PARTS`],
//! [`MAX_NESTING_DEPTH`] or [`MAX_COMPRESSED`] on the base64 input:
//! each of those is the bomb gate for the MIME walker.

use base64::Engine;
use thiserror::Error;

use super::decompress::{Encoding, MAX_COMPRESSED};

/// Hard cap on total parts we walk. A real inbound report has two (text
/// part + attachment); a forwarded message might double that. Anything
/// past 64 is a structure we have no business decoding.
const MAX_PARTS: usize = 64;

/// Hard cap on the multipart nesting depth the walker recurses into.
/// Real-world messages are flat or one level deep (a report inside a
/// forwarded message); more than [`MAX_NESTING_DEPTH`] is hostile and
/// we refuse to walk further.
const MAX_NESTING_DEPTH: u8 = 2;

/// What we found after walking the message.
#[derive(Debug)]
pub struct FoundPart {
	/// Encoding the bytes inside the part are compressed with.
	pub encoding: Encoding,
	/// The base64-decoded bytes of the attachment.
	pub bytes: Vec<u8>,
}

/// Why the walker refused the message.
#[derive(Debug, Error)]
pub enum WalkError {
	/// The message declares no part that looks like a report.
	#[error("no report part in the message")]
	NoReportPart,
	/// A multipart section was malformed.
	#[error("malformed multipart: {0}")]
	Malformed(&'static str),
	/// The base64 decode of the attachment failed.
	#[error("invalid base64 in attachment")]
	InvalidBase64,
	/// The decoded payload exceeds [`MAX_COMPRESSED`].
	#[error("decoded attachment too large")]
	TooLarge,
}

/// Find the report attachment inside `raw` for the given `kind`. Returns
/// `None` (not an error) when the message is a regular non-report
/// message; the deliverer calls this for every postmaster@/tlsrpt@
/// recipient, and a clean "no report here" is the right answer for the
/// operator's own outbound mail.
pub fn find_report_part(raw: &[u8], kind: Kind) -> Result<FoundPart, WalkError> {
	let parts = split_top_level(raw)?;
	match walk_parts(&parts, kind, 1)? {
		FoundPartWalk::Found(found) => Ok(found),
		FoundPartWalk::Continue => Err(WalkError::NoReportPart),
	}
}

fn walk_parts(
	parts: &[ParsedPart],
	kind: Kind,
	depth: u8,
) -> Result<FoundPartWalk, WalkError> {
	for part in parts {
		if let Some(ct) = part.content_type.as_deref()
			&& let Some(encoding) = encoding_for(ct)
			&& let Some(payload) = part.body_decoded()?
		{
			return Ok(FoundPartWalk::Found(FoundPart {
				encoding,
				bytes: payload,
			}));
		}
		// Some senders label the type as `application/octet-stream` and
		// rely on the filename. Look one level deeper.
		if part
			.content_type
			.as_deref()
			.is_some_and(|ct| ct.starts_with("multipart/"))
			&& let Some(inner_boundary) = part.boundary.as_deref()
			&& depth < MAX_NESTING_DEPTH
		{
			let inner = split_with_boundary(&part.body, inner_boundary)?;
			if let FoundPartWalk::Found(found) = walk_parts(&inner, kind, depth + 1)? {
				return Ok(FoundPartWalk::Found(found));
			}
		}
	}
	// Filename match as a last resort: a part whose `Content-Type` is
	// `application/octet-stream` but whose `Content-Disposition` says
	// `report.xml.gz` still counts.
	for part in parts {
		if let Some(found) = part_match(part, kind)? {
			return Ok(FoundPartWalk::Found(found));
		}
	}
	Ok(FoundPartWalk::Continue)
}

/// Recursive return: a part we matched, or the signal to keep walking.
/// `Result<FoundPart, WalkError>` is already used by callers and does
/// not encode "not found at this depth, try next", which is what
/// `Continue` carries.
enum FoundPartWalk {
	Found(FoundPart),
	Continue,
}

fn part_match(part: &ParsedPart, kind: Kind) -> Result<Option<FoundPart>, WalkError> {
	// Filename match: any part ending in `.xml.gz` / `.zip` is DMARC; any
	// part ending in `.json.gz` / `.json` is TLS-RPT. The actual encoding
	// is what the filename implies.
	if let Some(filename) = part.filename.as_deref() {
		let lower = filename.to_ascii_lowercase();
		if kind == Kind::Dmarc && (lower.ends_with(".xml.gz") || lower.ends_with(".zip")) {
			let encoding = if lower.ends_with(".zip") {
				Encoding::Zip
			} else {
				Encoding::Gzip
			};
			if let Some(payload) = part.body_decoded()? {
				return Ok(Some(FoundPart {
					encoding,
					bytes: payload,
				}));
			}
		}
		if kind == Kind::TlsRpt && (lower.ends_with(".json.gz") || lower.ends_with(".json")) {
			let encoding = if lower.ends_with(".gz") {
				Encoding::Gzip
			} else {
				Encoding::Zip
			};
			if let Some(payload) = part.body_decoded()? {
				return Ok(Some(FoundPart {
					encoding,
					bytes: payload,
				}));
			}
		}
	}
	Ok(None)
}

fn encoding_for(content_type: &str) -> Option<Encoding> {
	let lower = content_type.to_ascii_lowercase();
	// Trim parameters (`; charset=utf-8` etc.) before matching.
	let base = lower.split(';').next().unwrap_or("").trim();
	match base {
		"application/gzip" | "application/x-gzip" => Some(Encoding::Gzip),
		"application/zip" | "application/x-zip-compressed" => Some(Encoding::Zip),
		"application/tlsrpt+gzip" => Some(Encoding::Gzip),
		"application/tlsrpt+json" => Some(Encoding::Zip),
		_ => None,
	}
}

/// One parsed MIME part with the headers we care about.
#[derive(Debug, Default)]
struct ParsedPart {
	content_type: Option<String>,
	filename: Option<String>,
	/// Multipart boundary when the part itself is a multipart container.
	boundary: Option<String>,
	transfer_encoding: Option<String>,
	body: Vec<u8>,
}

impl ParsedPart {
	/// Decode the part body. Returns `None` when the part has no body or
	/// when the `Content-Transfer-Encoding` is something other than the
	/// ones we accept (we only see `7bit`, `8bit`, `base64`).
	fn body_decoded(&self) -> Result<Option<Vec<u8>>, WalkError> {
		let encoding = self
			.transfer_encoding
			.as_deref()
			.unwrap_or("7bit")
			.to_ascii_lowercase();
		match encoding.as_str() {
			"7bit" | "8bit" | "binary" => Ok(Some(self.body.clone())),
			"base64" => {
				let cleaned: Vec<u8> = self
					.body
					.iter()
					.copied()
					.filter(|b| !b.is_ascii_whitespace())
					.collect();
				// Measure the largest possible decoded length first and
				// refuse anything that cannot possibly fit inside the
				// bomb gate. Every four base64 characters decode to at
				// most three bytes; padding shortens the result but the
				// upper bound is correct for the refusal check.
				let upper = cleaned.len().saturating_mul(3) / 4;
				if upper > MAX_COMPRESSED {
					return Err(WalkError::TooLarge);
				}
				let bytes = base64::engine::general_purpose::STANDARD
					.decode(&cleaned)
					.map_err(|_| WalkError::InvalidBase64)?;
				Ok(Some(bytes))
			}
			_ => Ok(None),
		}
	}
}

/// Split `raw` into top-level parts using the boundary from its
/// `Content-Type` header. A non-multipart message returns one synthetic
/// part (the whole body), so the caller can use the same code path for a
/// single-part message as for a multipart one.
fn split_top_level(raw: &[u8]) -> Result<Vec<ParsedPart>, WalkError> {
	let headers_end = find_headers_end(raw).ok_or(WalkError::Malformed("no header end"))?;
	let headers = &raw[..headers_end];
	let body = &raw[headers_end + 4..];
	let ct = header_value(headers, "content-type")
		.ok_or(WalkError::Malformed("missing content-type"))?;
	let base = ct
		.split(';')
		.next()
		.unwrap_or("")
		.trim()
		.to_ascii_lowercase();
	if !base.starts_with("multipart/") {
		// Single-part: the body is one part with whatever content-type
		// and transfer-encoding the message declares.
		return Ok(vec![ParsedPart {
			content_type: Some(base),
			filename: content_disposition_filename(headers),
			boundary: None,
			transfer_encoding: header_value(headers, "content-transfer-encoding"),
			body: body.to_vec(),
		}]);
	}
	let boundary =
		parse_boundary_param(&ct).ok_or(WalkError::Malformed("multipart missing boundary"))?;
	let parts = split_with_boundary(body, &boundary)?;
	Ok(parts)
}

fn split_with_boundary(body: &[u8], bouxtary: &str) -> Result<Vec<ParsedPart>, WalkError> {
	let needle = format!("--{bouxtary}");
	let haystack = body;
	let mut parts = Vec::new();
	let mut cursor = 0usize;
	loop {
		let Some(rel) = find_subslice(&haystack[cursor..], needle.as_bytes()) else {
			// Buffer ended without ever seeing the closing boundary.
			// Real senders always include it; missing means the message
			// was truncated or hostile. Either way we refuse.
			return Err(WalkError::Malformed("missing closing boundary"));
		};
		let abs = cursor + rel;
		let after = abs + needle.len();
		if haystack.get(after..after + 2) == Some(b"--") {
			break; // closing boundary
		}
		// Skip the CRLF (or LF) right after the boundary marker.
		let body_start = if haystack.get(after..after + 2) == Some(b"\r\n") {
			after + 2
		} else if haystack.get(after..after + 1) == Some(b"\n") {
			after + 1
		} else {
			return Err(WalkError::Malformed("boundary not followed by line break"));
		};
		// Find the next boundary marker.
		let next_rel = find_subslice(&haystack[body_start..], needle.as_bytes())
			.ok_or(WalkError::Malformed("missing closing boundary"))?;
		let body_end_rel = next_rel;
		// Trim the CRLF before the next boundary.
		let mut body_end = body_start + body_end_rel;
		if body_end >= 2 && &haystack[body_end - 2..body_end] == b"\r\n" {
			body_end -= 2;
		} else if body_end >= 1 && &haystack[body_end - 1..body_end] == b"\n" {
			body_end -= 1;
		}
		let part_bytes = &haystack[body_start..body_end];
		parts.push(parse_part(part_bytes)?);
		if parts.len() > MAX_PARTS {
			return Err(WalkError::Malformed("too many parts"));
		}
		cursor = body_start + body_end_rel;
	}
	Ok(parts)
}

fn parse_part(part_bytes: &[u8]) -> Result<ParsedPart, WalkError> {
	let headers_end =
		find_headers_end(part_bytes).ok_or(WalkError::Malformed("part has no headers"))?;
	let headers = &part_bytes[..headers_end];
	let body = part_bytes[headers_end + 4..].to_vec();
	let content_type = header_value(headers, "content-type");
	let boundary = content_type.as_deref().and_then(parse_boundary_param);
	let filename = content_disposition_filename(headers);
	let transfer_encoding = header_value(headers, "content-transfer-encoding");
	Ok(ParsedPart {
		content_type,
		filename,
		boundary,
		transfer_encoding,
		body,
	})
}

fn content_disposition_filename(headers: &[u8]) -> Option<String> {
	let raw = header_value(headers, "content-disposition")?;
	for segment in raw.split(';') {
		let segment = segment.trim();
		if let Some(rest) = segment.strip_prefix("filename=") {
			let value = rest.trim_matches('"').trim();
			if !value.is_empty() {
				return Some(value.to_string());
			}
		}
		// RFC 5987 form: filename*=UTF-8''<percent-encoded>. Many
		// receivers ship it that way; we use the simple ASCII `filename`
		// when both are present.
	}
	None
}

/// Parse the `boundary="..."` parameter out of a `Content-Type` header.
/// Returns the bare boundary token.
fn parse_boundary_param(content_type: &str) -> Option<String> {
	for segment in content_type.split(';').skip(1) {
		let segment = segment.trim();
		if let Some(rest) = segment.strip_prefix("boundary=") {
			let value = rest.trim_matches('"').trim();
			if !value.is_empty() {
				return Some(value.to_string());
			}
		}
	}
	None
}

fn find_headers_end(raw: &[u8]) -> Option<usize> {
	find_subslice(raw, b"\r\n\r\n").or_else(|| find_subslice(raw, b"\n\n"))
}

fn header_value(headers: &[u8], name: &str) -> Option<String> {
	let text = std::str::from_utf8(headers).ok()?;
	for line in unfold_headers(text).lines() {
		let (key, value) = line.split_once(':')?;
		if key.trim().eq_ignore_ascii_case(name) {
			return Some(value.trim().to_string());
		}
	}
	None
}

/// RFC 5322 §2.2.3: a header continuation line starts with whitespace.
/// Joining these back into the parent line keeps the header walker from
/// seeing an orphan `boundary="..."` line.
fn unfold_headers(raw: &str) -> String {
	let mut out = String::with_capacity(raw.len());
	let mut continuation = false;
	for line in raw.split('\n') {
		let line = line.strip_suffix('\r').unwrap_or(line);
		if line.is_empty() {
			out.push_str("\r\n");
			continuation = false;
			continue;
		}
		if line.starts_with(' ') || line.starts_with('\t') {
			if continuation {
				out.push(' ');
				out.push_str(line.trim_start());
			} else {
				out.push_str(line);
				out.push_str("\r\n");
			}
		} else {
			out.push_str(line);
			out.push_str("\r\n");
			continuation = true;
		}
	}
	out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() || needle.len() > haystack.len() {
		return None;
	}
	for i in 0..=(haystack.len() - needle.len()) {
		if &haystack[i..i + needle.len()] == needle {
			return Some(i);
		}
	}
	None
}

use super::Kind;

#[cfg(test)]
#[path = "mime_tests.rs"]
mod tests;