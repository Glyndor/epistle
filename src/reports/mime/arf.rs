//! Find the two parts of an ARF feedback report (RFC 5965) in an inbound
//! message: the machine-readable fields and the headers of the message the
//! report is about.
//!
//! Same rules as the aggregate-report walker above: the multipart is split by
//! the shared splitter with its part, depth and boundary bounds, and a message
//! larger than [`MAX_ARF`] is refused outright rather than read in part, so no
//! field is ever taken from a truncated report.

use super::{
	WalkError, find_headers_end, header_value, parse_boundary_param, split_top_level,
	unfold_headers,
};

/// Largest message read as a feedback report, in bytes. A report holds the
/// fields and the headers of one message, a few kilobytes; providers that
/// quote the whole message stay far below this.
pub(crate) const MAX_ARF: usize = 256 * 1024;

/// The parts of a feedback report that the receiver reads.
#[derive(Debug)]
pub(crate) struct ArfParts {
	/// The body of the `message/feedback-report` part: `Name: value` lines.
	pub fields: Vec<u8>,
	/// The header block of the reported message, from the `message/rfc822`
	/// or `text/rfc822-headers` part. Empty when the report quotes none.
	pub original_headers: Vec<u8>,
}

/// Read `raw` as `multipart/report; report-type=feedback-report`.
///
/// Fails when the message is larger than [`MAX_ARF`], is not that type at its
/// top level, or has no machine-readable part or more than one: a report that
/// can be read two ways is not read at all.
pub(crate) fn find_arf_parts(raw: &[u8]) -> Result<ArfParts, WalkError> {
	if raw.len() > MAX_ARF {
		return Err(WalkError::TooLarge);
	}
	let (headers_end, _) = find_headers_end(raw).ok_or(WalkError::Malformed("no header end"))?;
	let content_type = header_value(&raw[..headers_end], "content-type")
		.ok_or(WalkError::Malformed("no content type"))?;
	if !is_feedback_report(&content_type) {
		return Err(WalkError::NoReportPart);
	}
	let mut fields = None;
	let mut original_headers = Vec::new();
	for part in split_top_level(raw)? {
		let base = part
			.content_type
			.as_deref()
			.map(|value| {
				value
					.split(';')
					.next()
					.unwrap_or("")
					.trim()
					.to_ascii_lowercase()
			})
			.unwrap_or_default();
		match base.as_str() {
			"message/feedback-report" => {
				if fields.is_some() {
					return Err(WalkError::Malformed("more than one feedback-report part"));
				}
				let body = part.body_decoded()?.ok_or(WalkError::Malformed(
					"feedback-report part has an unknown encoding",
				))?;
				fields = Some(body);
			}
			"message/rfc822" | "text/rfc822-headers" if original_headers.is_empty() => {
				let end = find_headers_end(&part.body).map_or(part.body.len(), |(end, _)| end);
				original_headers = part.body[..end].to_vec();
			}
			_ => {}
		}
	}
	Ok(ArfParts {
		fields: fields.ok_or(WalkError::NoReportPart)?,
		original_headers,
	})
}

/// The value of the first field `name` in a block of `Name: value` lines,
/// continuation lines joined. A line without a colon is skipped and a byte
/// that is not UTF-8 reads as U+FFFD, so one odd line never hides the fields
/// after it.
pub(crate) fn field(block: &[u8], name: &str) -> Option<String> {
	let text = String::from_utf8_lossy(block);
	let mut found: Option<String> = None;
	for line in unfold_headers(&text).lines() {
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			found = Some(value.trim().to_string());
			break;
		}
	}
	found
}

/// Whether a `Content-Type` value is `multipart/report` with
/// `report-type=feedback-report`.
fn is_feedback_report(content_type: &str) -> bool {
	let lower = content_type.to_ascii_lowercase();
	if lower.split(';').next().map(str::trim) != Some("multipart/report") {
		return false;
	}
	lower.split(';').skip(1).any(|segment| {
		segment.split_once('=').is_some_and(|(name, value)| {
			name.trim() == "report-type" && value.trim().trim_matches('"') == "feedback-report"
		})
	}) && parse_boundary_param(content_type).is_some()
}
