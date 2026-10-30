//! Requested text values, charset conversion and UTF-8 byte limits.

use mail_parser::{Message, MessagePart, PartFlags};
use serde_json::{Map, Value, json};

pub(super) fn body_values(
	message: &Message<'_>,
	tree: &Value,
	text: &[&Value],
	html: &[&Value],
	args: &Value,
) -> Value {
	let mut selected = Vec::new();
	if args["fetchAllBodyValues"] == true {
		collect_leaves(tree, &mut selected);
	} else {
		if args["fetchTextBodyValues"] == true {
			selected.extend_from_slice(text);
		}
		if args["fetchHTMLBodyValues"] == true {
			selected.extend_from_slice(html);
		}
	}
	let max_bytes = args["maxBodyValueBytes"]
		.as_u64()
		.and_then(|n| usize::try_from(n).ok())
		.unwrap_or(0);
	let parts: Vec<_> = message.root().parts().collect();
	let mut result = Map::new();
	for node in selected {
		if !node["type"]
			.as_str()
			.is_some_and(|t| t.starts_with("text/"))
		{
			continue;
		}
		let Some(id) = node["partId"].as_str() else {
			continue;
		};
		let Some(part) = id.parse::<usize>().ok().and_then(|i| parts.get(i)) else {
			continue;
		};
		let (mut content, encoding_problem) = decoded_text(part);
		let truncated = max_bytes > 0 && content.len() > max_bytes;
		if truncated {
			let mut end = max_bytes;
			while !content.is_char_boundary(end) {
				end -= 1;
			}
			if node["type"] == "text/html" {
				let prefix = &content[..end];
				if let Some(start) = prefix.rfind('<')
					&& !prefix[start..].contains('>')
				{
					end = start;
				}
			}
			content.truncate(end);
		}
		result.insert(
			id.to_owned(),
			json!({"value":content,
			"isEncodingProblem":encoding_problem,"isTruncated":truncated}),
		);
	}
	Value::Object(result)
}

fn collect_leaves<'a>(part: &'a Value, selected: &mut Vec<&'a Value>) {
	let mut pending = vec![part];
	while let Some(part) = pending.pop() {
		if let Some(children) = part["subParts"].as_array() {
			pending.extend(children.iter().rev());
		} else {
			selected.push(part);
		}
	}
}

fn decoded_text(part: &MessagePart<'_>) -> (String, bool) {
	let octets = super::decoded_octets(part);
	let charset = part
		.content_type()
		.and_then(|ct| ct.attribute("charset"))
		.unwrap_or("us-ascii");
	let utf8 = matches!(
		charset.to_ascii_lowercase().as_str(),
		"utf-8"
			| "utf8" | "unicode11utf8"
			| "unicode20utf8"
			| "x-unicode20utf8"
			| "unicode-1-1-utf-8"
	);
	let (content, charset_problem) = if utf8 {
		(
			String::from_utf8_lossy(&octets).into_owned(),
			std::str::from_utf8(&octets).is_err(),
		)
	} else if let Some(decoder) =
		mail_parser::decoders::charsets::charset_decoder(charset.as_bytes())
	{
		let content = decoder(&octets);
		let problem = content.contains('\u{fffd}');
		(content, problem)
	} else {
		(String::from_utf8_lossy(&octets).into_owned(), true)
	};
	let unknown_transfer = part.content_transfer_encoding().is_some_and(|encoding| {
		!matches!(
			encoding.trim().to_ascii_lowercase().as_str(),
			"7bit" | "8bit" | "binary" | "base64" | "quoted-printable"
		)
	});
	(
		content.replace("\r\n", "\n"),
		legacy_structure_problem(part)
			|| transfer_problem(part)
			|| charset_problem
			|| unknown_transfer,
	)
}

// The removed flag included transfer-decoding failures. Preserve the old
// fallible codec check instead of treating 1.0's best-effort output as success.
fn transfer_problem(part: &MessagePart<'_>) -> bool {
	match part.content_transfer_encoding().map(str::trim) {
		Some(encoding) if encoding.eq_ignore_ascii_case("base64") => {
			crate::util::mail_parser::base64_decode(part.raw_body()).is_none()
		}
		Some(encoding) if encoding.eq_ignore_ascii_case("quoted-printable") => {
			crate::util::mail_parser::quoted_printable_decode(part.raw_body()).is_none()
		}
		_ => false,
	}
}

// New structural flags also describe recoveries that 0.11 accepted without
// setting is_encoding_problem (for example a delimiter in mid-line).
fn legacy_structure_problem(part: &MessagePart<'_>) -> bool {
	let flags = part.flags();
	flags.contains(PartFlags::NO_BLANK_LINE)
		|| (flags.contains(PartFlags::MISSING_DELIMITER) && !part.is_multipart())
}
