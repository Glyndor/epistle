//! Tests for the modified UTF-7 mailbox-name codec (RFC 3501 §5.1.3).

use super::*;

#[test]
fn ascii_names_are_unchanged() {
	for name in ["INBOX", "Sent Items", "a-b_c.d", "~peter/mail"] {
		assert_eq!(encode(name), name);
		assert_eq!(decode(name).as_deref(), Some(name));
	}
}

#[test]
fn encodes_the_rfc_examples() {
	// RFC 3501 §5.1.3 and RFC 2152-style samples.
	assert_eq!(
		encode("~peter/mail/台北/日本語"),
		"~peter/mail/&U,BTFw-/&ZeVnLIqe-"
	);
	assert_eq!(encode("Entwürfe"), "Entw&APw-rfe");
	assert_eq!(encode("Café"), "Caf&AOk-");
	assert_eq!(encode("A&B"), "A&-B");
	// A character outside the BMP travels as a surrogate pair.
	assert_eq!(encode("x😀"), "x&2D3eAA-");
}

#[test]
fn decodes_what_it_encodes() {
	for name in [
		"~peter/mail/台北/日本語",
		"Entwürfe",
		"Café",
		"A&B",
		"x😀",
		"Входящие",
	] {
		assert_eq!(decode(&encode(name)).as_deref(), Some(name), "{name}");
	}
}

#[test]
fn rejects_malformed_and_non_canonical_input() {
	for encoded in [
		"Caf&AOk",    // unterminated run
		"Caf&AO!-",   // character outside the modified base64 alphabet
		"Caf&AOl-",   // leftover bits that are not zero
		"Caf&AOkA-",  // an odd number of octets
		"Caf&AGE-",   // printable ASCII ("a") must not be encoded
		"&AOk-&AOk-", // two adjacent runs must be one
		"Café",       // raw 8-bit is not modified UTF-7
		"&2D0-",      // unpaired surrogate
	] {
		assert_eq!(decode(encoded), None, "{encoded}");
	}
}
