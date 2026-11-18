//! Read and grow the header block as a whole: where it ends, the values of a
//! field, and lines put at its top.

use super::{same_name, split_field};

/// Byte index where the first empty line starts. Everything before it is the
/// header block, and the empty line and what follows are the body. Returns
/// `data.len()` when no empty line is present.
pub(super) fn header_block_end(data: &[u8]) -> usize {
	crate::util::header_block::split_at_blank_line(data).0.len()
}

/// The unfolded, trimmed values of every `name` field in the header block
/// of `data`, in order. Bytes that are not UTF-8 are replaced.
pub fn header_values(data: &[u8], name: &str) -> Vec<String> {
	let header_end = header_block_end(data);
	let mut values: Vec<String> = Vec::new();
	let mut collecting = false;
	for line in data[..header_end].split_inclusive(|&b| b == b'\n') {
		if matches!(line.first(), Some(b' ' | b'\t')) {
			if collecting && let Some(value) = values.last_mut() {
				value.push(' ');
				value.push_str(String::from_utf8_lossy(line).trim());
			}
			continue;
		}
		let split = split_field(line);
		collecting = split.is_some_and(|(field, _)| same_name(field, name.as_bytes()));
		if collecting && let Some((_, value)) = split {
			values.push(String::from_utf8_lossy(value).trim().to_string());
		}
	}
	for value in &mut values {
		*value = value.trim().to_string();
	}
	values
}

/// Put `lines` at the top of the header block of `data`, shifting the message
/// up inside the same buffer, and do nothing when there is nothing to add.
/// Each line in `lines` carries its own CRLF terminator.
pub fn prepend_header_block(data: &mut Vec<u8>, lines: &str) {
	if lines.is_empty() {
		return;
	}
	let ending = std::str::from_utf8(crate::util::header_block::line_ending(data))
		.expect("ASCII line ending");
	let prefix = if ending == "\n" {
		lines.replace("\r\n", "\n")
	} else {
		lines.to_string()
	};
	let len = data.len();
	data.reserve_exact(prefix.len());
	data.resize(len + prefix.len(), 0);
	data.copy_within(..len, prefix.len());
	data[..prefix.len()].copy_from_slice(prefix.as_bytes());
}

/// Prepend the two spam-marking headers a downstream client uses to tell
/// ham from junk: `X-Spam-Status: Yes` plus the raw probability in
/// `X-Spam-Score`. The injector only fires when the corpus returned a
/// score at or above `bayes_junk_at`: a below-threshold message must not
/// grow headers the recipient did not ask for.
///
/// Header lines are inserted at the top of the existing header block (the
/// prefix before the first blank line, CRLF or LF). The byte boundary is
/// not re-scanned for "X-Spam-Status" already present: in practice the
/// SMTP server runs this exactly once per accepted message, so a
/// duplicate pass would imply a real bug in the call site, not a
/// repeated correlate header.
pub fn inject_spam_headers(data: &[u8], score: f64) -> Vec<u8> {
	let header_end = header_block_end(data);
	let (headers, body) = data.split_at(header_end);
	// Six decimals is plenty for a probability and avoids leaking the
	// floating-point noise that `f64::to_string` would emit.
	let prefix = format!("X-Spam-Status: Yes\r\nX-Spam-Score: {score:.6}\r\n");
	let mut out = Vec::with_capacity(data.len() + prefix.len());
	out.extend_from_slice(prefix.as_bytes());
	out.extend_from_slice(headers);
	out.extend_from_slice(body);
	out
}
