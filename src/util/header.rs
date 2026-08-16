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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn preserves_benign_value() {
		assert_eq!(sanitize_header_value("Lunch?"), "Lunch?");
		assert_eq!(sanitize_header_value("hola, ¿qué tal?"), "hola, ¿qué tal?");
		assert_eq!(sanitize_header_value(""), "");
	}

	#[test]
	fn strips_cr_lf_to_prevent_header_injection() {
		let input = "foo\r\nBcc: attacker@evil.example";
		let sanitized = sanitize_header_value(input);
		assert!(!sanitized.contains('\r'), "{sanitized:?}");
		assert!(!sanitized.contains('\n'), "{sanitized:?}");
		assert_eq!(sanitized, "foo  Bcc: attacker@evil.example");
	}

	#[test]
	fn strips_nul_and_tab() {
		let sanitized = sanitize_header_value("before\0after\twith\ttabs");
		assert!(!sanitized.chars().any(|c| c.is_control()), "{sanitized:?}");
		assert_eq!(sanitized, "before after with tabs");
	}

	#[test]
	fn caps_to_max_byte_length() {
		let input = "x".repeat(2_000);
		let sanitized = sanitize_header_value(&input);
		assert_eq!(sanitized.len(), MAX_HEADER_VALUE_LEN);
		assert_eq!(sanitized.chars().count(), MAX_HEADER_VALUE_LEN);
	}

	#[test]
	fn cap_respects_utf8_boundaries() {
		// 'ñ' is two bytes; we must not split a multibyte character mid-codepoint.
		let input = "ñ".repeat(2_000);
		let sanitized = sanitize_header_value(&input);
		assert!(sanitized.len() <= MAX_HEADER_VALUE_LEN);
		assert!(sanitized.chars().all(|c| c == 'ñ'));
	}

	#[test]
	fn is_idempotent() {
		let inputs = [
			"",
			"Lunch?",
			"foo\r\nBcc: attacker@evil.example",
			"\0\0\0",
			"\t\n\r",
			"\r\n\r\n",
			&"x".repeat(2_000),
			"hola, ¿qué tal?\r\nBcc: attacker@evil.example",
		];
		for input in inputs {
			let once = sanitize_header_value(input);
			let twice = sanitize_header_value(&once);
			assert_eq!(once, twice, "input: {input:?}");
		}
	}
}
