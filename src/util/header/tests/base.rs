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
