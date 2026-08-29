//! Unit tests for the LLM classifier: pure logic (no HTTP).

use super::*;

#[test]
fn parse_reply_quarantines_on_high_confidence_spam() {
	assert_eq!(
		parse_reply(br#"{"spam":true,"confidence":0.9}"#),
		HookVerdict::Quarantine
	);
}

#[test]
fn parse_reply_accepts_on_low_confidence_spam() {
	assert_eq!(
		parse_reply(br#"{"spam":true,"confidence":0.5}"#),
		HookVerdict::Accept
	);
}

#[test]
fn parse_reply_accepts_when_not_spam() {
	assert_eq!(
		parse_reply(br#"{"spam":false,"confidence":0.99}"#),
		HookVerdict::Accept
	);
}

#[test]
fn parse_reply_fails_open_on_malformed_json() {
	assert_eq!(parse_reply(b"not json"), HookVerdict::Accept);
	assert_eq!(parse_reply(b""), HookVerdict::Accept);
	assert_eq!(parse_reply(br#"{"spam":true}"#), HookVerdict::Accept);
}

#[test]
fn parse_reply_fails_open_on_out_of_range_confidence() {
	// NaN and out-of-range values don't shape into our verdict: the model
	// being uncertain is treated as "not high-confidence spam".
	assert_eq!(
		parse_reply(br#"{"spam":true,"confidence":-0.1}"#),
		HookVerdict::Accept
	);
}

#[test]
fn extract_safe_headers_keeps_only_trusted_three() {
	let raw = b"From: alice@example.org\r\n\
Subject: hi there\r\n\
Reply-To: bob@example.org\r\n\
Authorization: Bearer should-not-leak\r\n\
Received: from foo by bar\r\n\
DKIM-Signature: v=1; a=rsa-sha256\r\n\
\r\n\
body";
	let kept = extract_safe_headers(raw);
	let joined = kept.join("\n");
	assert!(joined.contains("From: alice@example.org"), "{joined}");
	assert!(joined.contains("Subject: hi there"), "{joined}");
	assert!(joined.contains("Reply-To: bob@example.org"), "{joined}");
	assert!(!joined.contains("Authorization"), "{joined}");
	assert!(!joined.contains("Received"), "{joined}");
	assert!(!joined.contains("DKIM-Signature"), "{joined}");
}

#[test]
fn extract_safe_headers_unfolds_continued_subject() {
	let raw = b"From: alice@example.org\nSubject: hello\n world\nReply-To: bob@example.org\n\nbody";
	let kept = extract_safe_headers(raw);
	let subject = kept
		.iter()
		.find(|l| l.starts_with("Subject:"))
		.expect("subject kept");
	assert!(subject.contains("hello world"), "{subject}");
}

#[test]
fn body_bytes_caps_at_max() {
	let raw = b"From: x\r\nSubject: y\r\n\r\nABCDEFGHIJ";
	assert_eq!(body_bytes(raw, 5), b"ABCDE");
	assert_eq!(body_bytes(raw, 1000), b"ABCDEFGHIJ");
}

#[test]
fn body_bytes_handles_no_blank_line() {
	let raw = b"From: x Subject: y\r\nNOTBLANK";
	// No blank-line separator: every byte is treated as body, so a small
	// cap clamps to the limit.
	assert_eq!(body_bytes(raw, 100), raw.as_slice());
	assert_eq!(body_bytes(raw, 5).len(), 5);
}

#[test]
fn build_request_body_includes_truncated_body() {
	let raw = b"From: a@b\r\nSubject: hi\r\n\r\nabcdefghij";
	let body = build_request_body(4, raw);
	let text = String::from_utf8_lossy(&body);
	assert!(text.contains("From: a@b"), "{text}");
	assert!(text.contains("Subject: hi"), "{text}");
	assert!(text.contains("abcd"), "{text}");
	assert!(!text.contains("efghij"), "{text}");
}

#[test]
fn openai_request_json_uses_provided_model_and_json_object_format() {
	let body = openai_request_json("gpt-test", b"hello");
	let text = String::from_utf8_lossy(&body);
	assert!(text.contains("\"model\":\"gpt-test\""), "{text}");
	assert!(
		text.contains("\"response_format\":{\"type\":\"json_object\"}"),
		"{text}"
	);
	assert!(text.contains("\"temperature\":0"), "{text}");
	assert!(text.contains("hello"), "{text}");
}

#[test]
fn find_body_start_locates_blank_line() {
	let raw = b"From: x\r\nSubject: y\r\n\r\nbody";
	// Body starts after the CRLFCRLF separator at byte index 19.
	assert_eq!(find_body_start(raw), Some(23));
}

#[test]
fn find_body_start_falls_back_to_lf_lf() {
	let raw = b"From: x\nSubject: y\n\nbody";
	// CRLF not present: tolerate bare LFLF.
	assert_eq!(find_body_start(raw), Some(20));
}

#[test]
fn find_body_start_returns_none_when_missing() {
	let raw = b"From: x Subject: y\r\nNOTBLANK";
	assert_eq!(find_body_start(raw), None);
}
