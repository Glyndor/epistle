//! Canonicalization vectors taken from RFC 6376 section 3.4, and the
//! properties the relaxed body algorithm has to hold.
//!
//! The inputs and the expected outputs come from the RFC, not from this
//! project's signer: an implementation that agrees with itself on the wrong
//! bytes passes its own tests and fails at every receiver, so the test that
//! matters takes its input from somewhere else.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// The body of the message of RFC 6376 section 3.4.5 example 1. The RFC
/// prints it as:
///
/// ```text
/// <SP> C <SP><CRLF>
/// D <SP><HTAB><SP> E <CRLF>
/// <CRLF>
/// <CRLF>
/// ```
const RFC6376_BODY: &[u8] = b" C \r\nD \t E\r\n\r\n\r\n";

/// The relaxed body of that message, as the RFC prints it:
///
/// ```text
/// <SP> C <CRLF>
/// D <SP> E <CRLF>
/// ```
const RFC6376_RELAXED_BODY: &[u8] = b" C\r\nD E\r\n";

/// The simple body of that message, as the RFC prints it:
///
/// ```text
/// <SP> C <SP><CRLF>
/// D <SP><HTAB><SP> E <CRLF>
/// ```
const RFC6376_SIMPLE_BODY: &[u8] = b" C \r\nD \t E\r\n";

/// The relaxed headers of that message, as the RFC prints them:
///
/// ```text
/// a:X <CRLF>
/// b:Y <SP> Z <CRLF>
/// ```
///
/// The name arrives without the WSP the RFC prints before the colon of the
/// second field: every caller of this module trims it before calling, so the
/// name that reaches here never carries it.
#[test]
fn relaxed_header_matches_the_rfc6376_example() {
	assert_eq!(header(Canon::Relaxed, "A", " X"), "a:X\r\n");
	assert_eq!(header(Canon::Relaxed, "B", " Y \t\r\n\t Z  "), "b:Y Z\r\n");
}

/// The relaxed body of the message of RFC 6376 section 3.4.5 example 1.
#[test]
fn relaxed_body_matches_the_rfc6376_example() {
	assert_eq!(body(Canon::Relaxed, RFC6376_BODY), RFC6376_RELAXED_BODY);
}

/// The simple body of the message of RFC 6376 section 3.4.5 example 1.
#[test]
fn simple_body_matches_the_rfc6376_example() {
	assert_eq!(body(Canon::Simple, RFC6376_BODY), RFC6376_SIMPLE_BODY);
}

/// RFC 6376 section 3.4.3 publishes the digest of the simple canonicalization
/// of an empty body, and section 3.4.4 the digest of the relaxed one.
#[test]
fn the_empty_body_hashes_as_the_rfc_says() {
	let simple = body(Canon::Simple, b"");
	let relaxed = body(Canon::Relaxed, b"");
	assert_eq!(simple, b"\r\n");
	assert_eq!(relaxed, b"");
	assert_eq!(
		BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &simple)),
		"frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
	);
	assert_eq!(
		BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &relaxed)),
		"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	);
}

/// The relaxed body reduces every run of WSP to one space, including the one
/// at the start of the line: only the WSP at the end of the line goes away.
#[test]
fn relaxed_body_keeps_the_leading_whitespace_as_one_space() {
	assert_eq!(body(Canon::Relaxed, b"Hello\r\n"), b"Hello\r\n");
	assert_eq!(body(Canon::Relaxed, b" Hello\r\n"), b" Hello\r\n");
	assert_eq!(body(Canon::Relaxed, b"\tHello\r\n"), b" Hello\r\n");
	assert_eq!(body(Canon::Relaxed, b"  Hello  \r\n"), b" Hello\r\n");
}

/// The relaxed body ignores the empty lines at the end, so a body without
/// content hashes as the empty input.
#[test]
fn relaxed_body_of_a_body_without_content_is_empty() {
	assert_eq!(body(Canon::Relaxed, b"\r\n"), b"");
	assert_eq!(body(Canon::Relaxed, b" \r\n"), b"");
	assert_eq!(body(Canon::Relaxed, b"\t\r\n"), b"");
	assert_eq!(body(Canon::Relaxed, b"\r\n\r\n"), b"");
	assert_eq!(body(Canon::Relaxed, b" \r\n\r\n"), b"");
}

/// The empty lines in the middle of the body stay: only the ones at the end
/// are ignored.
#[test]
fn relaxed_body_keeps_the_empty_lines_in_the_middle() {
	assert_eq!(body(Canon::Relaxed, b"A\r\n\r\nB\r\n"), b"A\r\n\r\nB\r\n");
	assert_eq!(
		body(Canon::Relaxed, b"A\r\n\r\n\r\nB\r\n"),
		b"A\r\n\r\n\r\nB\r\n"
	);
	assert_eq!(body(Canon::Relaxed, b"A\r\n \r\nB\r\n"), b"A\r\n\r\nB\r\n");
}

/// Bodies that cover the shapes the two canonicalizations have to tell apart.
const BODIES: &[&[u8]] = &[
	b"",
	b"\r\n",
	b" \r\n",
	b"\t\r\n",
	b"\r\n\r\n",
	b"Hello\r\n",
	b" Hello\r\n",
	b"\tHello\r\n",
	b"Hello \t world\r\n",
	b"Hello\r\n\r\n",
	b"Hello\r\n\r\n\r\n",
	b"Hello \r\n",
	b"Hello\r\nWorld\r\n",
	b" Hello\r\n\r\n",
	b"Hello\r\n \r\n",
	b"Hello\r\n \r\nWorld\r\n",
	b" A\r\n\r\nB\r\n",
	b"Hello",
	b"Hello\n",
];

/// Canonicalizing a canonicalized body changes nothing: the relaxed body of
/// a relaxed body is the relaxed body.
#[test]
fn relaxed_body_is_idempotent() {
	for input in BODIES {
		let once = body(Canon::Relaxed, input);
		let twice = body(Canon::Relaxed, &once);
		assert_eq!(once, twice, "{input:?}");
	}
}

/// The empty lines at the end of the body are ignored, so adding or removing
/// them does not change the canonical body.
#[test]
fn relaxed_body_ignores_the_empty_lines_at_the_end() {
	for input in BODIES {
		let expected = body(Canon::Relaxed, input);
		for count in 1..=3 {
			let mut longer = input.to_vec();
			for _ in 0..count {
				longer.extend_from_slice(b"\r\n");
			}
			assert_eq!(body(Canon::Relaxed, &longer), expected, "{input:?}");
		}
	}
}
