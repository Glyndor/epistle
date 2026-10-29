//! Helpers for safely building RFC 5322 header fields from attacker-influenced
//! input. The auto-reply path reflects a remote sender's `Subject:` and
//! `Message-ID:` back into its own headers; a raw CRLF in those values would
//! inject forged headers (Bcc, X-*, …) into the reply we send.

/// Maximum octet length of an RFC 5322 line (988) — used as the byte cap on a
/// sanitized header value so a long input cannot inflate a single header line.
pub const MAX_HEADER_VALUE_LEN: usize = 998;

/// Flatten every control character (CR, LF, NUL, TAB, …) in `value` to a single
/// space and cap the result to [`MAX_HEADER_VALUE_LEN`] bytes.
///
/// Control characters are the injection vector: a CRLF in a header value
/// terminates the line and lets the next characters start a new header. By
/// collapsing CR/LF/NUL to a single space before the value reaches any
/// `format!`, the reply builder cannot be tricked into emitting a forged
/// header. The byte cap mirrors RFC 5322 §2.1.1's 998-octet line limit so a
/// single line cannot exceed the standard regardless of how long the source
/// value is.
///
/// The function is idempotent: applying it twice to any input yields the same
/// result as applying it once — printable input is unchanged, control
/// characters are already spaces after the first pass, and truncation cannot
/// re-trigger.
pub fn sanitize_header_value(value: &str) -> String {
	let mut result = String::with_capacity(value.len().min(MAX_HEADER_VALUE_LEN));
	for c in value.chars() {
		let replacement = if c.is_control() { ' ' } else { c };
		let additional = replacement.len_utf8();
		if result.len() + additional > MAX_HEADER_VALUE_LEN {
			break;
		}
		result.push(replacement);
	}
	result
}

/// The first field named `name` (ASCII case-insensitive), with its
/// continuation lines unfolded. Stops at the blank line that ends the header
/// block.
pub fn header_value(headers: &str, name: &str) -> Option<String> {
	let mut lines = headers.lines().peekable();
	while let Some(line) = lines.next() {
		if line.is_empty() {
			break;
		}
		if line.starts_with([' ', '\t']) {
			continue;
		}
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			let mut value = value.trim().to_string();
			while let Some(line) = lines.peek().filter(|l| l.starts_with([' ', '\t'])) {
				value.push(' ');
				value.push_str(line.trim());
				lines.next();
			}
			return Some(value);
		}
	}
	None
}

#[cfg(test)]
mod tests;
