//! Encoded words and reflected header values.

use epistle::util::encoded_word::decode;
use epistle::util::header::{MAX_HEADER_VALUE_LEN, header_value, sanitize_header_value};

use super::harness::bounded;

#[test]
fn nested_encoded_words_are_decoded_once_without_recursion() {
	bounded(|| {
		let inner = "=?UTF-8?Q?Bcc=3A_evil=40outside.test?=";
		let outer = format!(
			"=?UTF-8?Q?{}?=",
			inner
				.replace('=', "=3D")
				.replace('?', "=3F")
				.replace('_', "=5F")
		);
		let decoded = decode(&outer);
		assert_eq!(decoded, inner);
		assert!(decoded.len() <= outer.len());
	});
}

#[test]
fn giant_encoded_word_has_nonexpanding_output() {
	bounded(|| {
		let raw = format!("=?UTF-8?Q?{}?=", "=41".repeat(500_000));
		let decoded = decode(&raw);
		assert_eq!(decoded, "A".repeat(500_000));
		assert!(decoded.len() <= raw.len());
	});
}

#[test]
fn hundred_thousand_adjacent_encoded_words_drop_only_interword_whitespace() {
	bounded(|| {
		let raw = "=?UTF-8?Q?A?= \r\n\t".repeat(100_000);
		let decoded = decode(&raw);
		assert_eq!(decoded, format!("{} \r\n\t", "A".repeat(100_000)));
		assert!(decoded.len() <= raw.len());
	});
}

#[test]
fn malformed_giant_word_is_preserved_without_panic() {
	bounded(|| {
		let raw = format!("=?UTF-8?B?{}", "!".repeat(1 << 20));
		assert_eq!(decode(&raw), raw);
	});
}

#[test]
fn decoded_crlf_nul_and_unicode_controls_cannot_inject_reflected_headers() {
	bounded(|| {
		let decoded = decode("=?UTF-8?Q?ok=0D=0ABcc=3A_evil=40outside.test=00?=");
		assert!(decoded.contains("\r\nBcc:"));
		let safe = sanitize_header_value(&format!("{decoded}\u{0085}\tend"));
		assert_eq!(safe, "ok  Bcc: evil@outside.test   end");
		assert!(!safe.chars().any(char::is_control));
		assert_eq!(sanitize_header_value(&safe), safe);
	});
}

#[test]
fn giant_multibyte_reflected_header_is_capped_at_utf8_boundary() {
	bounded(|| {
		let input = "🦀".repeat(500_000);
		let safe = sanitize_header_value(&input);
		assert!(safe.len() <= MAX_HEADER_VALUE_LEN);
		assert_eq!(safe, "🦀".repeat(MAX_HEADER_VALUE_LEN / 4));
		assert_eq!(sanitize_header_value(&safe), safe);
	});
}

#[test]
fn ten_thousand_headers_cannot_make_body_or_duplicate_override_first_field() {
	bounded(|| {
		let mut raw = String::from("Subject: trusted\r\n folded\r\n");
		raw.push_str(&"X-Padding: x\r\n".repeat(10_000));
		raw.push_str("Subject: hostile\r\n\r\nReturn-Path: evil@outside.test\r\nSubject: body\r\n");
		assert_eq!(
			header_value(&raw, "subject").as_deref(),
			Some("trusted folded")
		);
		assert_eq!(header_value(&raw, "Return-Path"), None);
	});
}
