//! The content types a message carries, for the line that says a message is
//! not a report.

use super::{MAX_NESTING_DEPTH, ParsedPart, split_top_level, split_with_boundary};

/// Most types listed: a log line is not the place to dump a message.
const MAX_LISTED: usize = 16;

/// The content types of the message and of the parts inside it, in order,
/// without parameters and lowercased, as many as [`MAX_LISTED`]. Empty when
/// the message cannot be split.
pub(crate) fn content_types(raw: &[u8]) -> Vec<String> {
	let mut types = Vec::new();
	if let Ok(parts) = split_top_level(raw) {
		collect(&parts, 1, &mut types);
	}
	types
}

fn collect(parts: &[ParsedPart], depth: u8, types: &mut Vec<String>) {
	for part in parts {
		if types.len() >= MAX_LISTED {
			return;
		}
		let base = part
			.content_type
			.as_deref()
			.map(|ct| {
				ct.split(';')
					.next()
					.unwrap_or("")
					.trim()
					.to_ascii_lowercase()
			})
			.unwrap_or_else(|| "text/plain".to_string());
		let multipart = base.starts_with("multipart/");
		types.push(base);
		if multipart
			&& depth < MAX_NESTING_DEPTH
			&& let Some(boundary) = part.boundary.as_deref()
			&& let Ok(inner) = split_with_boundary(&part.body, boundary)
		{
			collect(&inner, depth + 1, types);
		}
	}
}
