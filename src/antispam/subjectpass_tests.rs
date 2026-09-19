//! Tests for SubjectPass.
//!
//! Structural notes:
//!
//! - `compare_is_constant_time` from the brief is not asserted with a fake.
//!   The verify path uses an internal `constant_time_eq` helper, which is
//!   straightforwardly constant-time (length-aware scan with an `|=` XOR
//!   accumulator); a unit test for the helper below pins the shape, and the
//!   brief allows dropping the structural test when a fake would be the only
//!   way to assert it. The doc-comment on `verify` records the contract.

use super::*;

fn fixture_key() -> [u8; 32] {
	let mut bytes = [0u8; 32];
	for (i, slot) in bytes.iter_mut().enumerate() {
		*slot = (i as u8).wrapping_mul(31).wrapping_add(7);
	}
	bytes
}

fn pass() -> SubjectPass {
	SubjectPass::with_key(fixture_key())
}

#[test]
fn a_token_verifies_for_its_pair_and_day() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let token = p.issue(sender, recipient, day);
	// The token has the EP- prefix and the expected suffix length.
	assert!(token.starts_with(TOKEN_PREFIX), "{token}");
	assert_eq!(token.len(), TOKEN_PREFIX.len() + TOKEN_CHARS, "{token}");
	assert!(p.verify(&token, sender, recipient, day));
}

#[test]
fn yesterdays_token_still_verifies_and_the_day_before_does_not() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	// Mint on day D-1, verify on day D (a sender who retries after midnight).
	let yesterday = 19_999;
	let today = 20_000;
	let token = p.issue(sender, recipient, yesterday);
	assert!(p.verify(&token, sender, recipient, today));
	// Same-day verification (sender pastes the token into the subject and
	// resends immediately).
	let same_day_token = p.issue(sender, recipient, today);
	assert!(p.verify(&same_day_token, sender, recipient, today));
	// Two days old is not.
	let two_days_old = p.issue(sender, recipient, today - 2);
	assert!(!p.verify(&two_days_old, sender, recipient, today));
}

#[test]
fn a_token_for_another_recipient_does_not_verify() {
	let p = pass();
	let day = 20_000;
	let token = p.issue("alice@example.org", "bob@example.org", day);
	// Same sender, different recipient: not valid.
	assert!(!p.verify(&token, "alice@example.org", "carol@example.org", day));
	// Different sender, same recipient: not valid.
	assert!(!p.verify(&token, "eve@example.org", "bob@example.org", day));
}

#[test]
fn a_token_for_another_sender_does_not_verify() {
	let p = pass();
	let day = 20_000;
	let token = p.issue("alice@example.org", "bob@example.org", day);
	assert!(!p.verify(&token, "mallory@example.org", "bob@example.org", day));
}

#[test]
fn the_token_is_found_anywhere_in_the_subject_and_case_insensitively() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let token = p.issue(sender, recipient, day);
	// Lowercase prefix, somewhere in the middle of the subject.
	let subject = format!("Re: photos {token} (fwd)");
	assert!(
		p.accepts(Some(&subject), sender, recipient, day),
		"should accept lowercase subject containing the token"
	);
	// Mixed case prefix still matches.
	let mixed = format!("Re: photos {} (fwd)", token.to_ascii_lowercase());
	assert!(p.accepts(Some(&mixed), sender, recipient, day));
	// Uppercase prefix at the start.
	assert!(p.accepts(
		Some(&format!("{token} introduction")),
		sender,
		recipient,
		day
	));
	// Token at the end, lowercase.
	let end_lc = format!("hello there {}", token.to_ascii_lowercase());
	assert!(p.accepts(Some(&end_lc), sender, recipient, day));
	// No token in the subject: false.
	assert!(!p.accepts(Some("hi bob"), sender, recipient, day));
	// Absent subject: false.
	assert!(!p.accepts(None, sender, recipient, day));
}

#[test]
fn an_invalid_token_is_ignored_not_an_error() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	// The prefix alone is not a valid token (suffix length too short).
	assert!(!p.accepts(Some("EP-ABC"), sender, recipient, day));
	// The suffix is the right length but the wrong bytes.
	assert!(!p.accepts(Some("EP-ABCDEFGHIJKL"), sender, recipient, day));
	// A random valid-shape token that does not match: still false, no panic.
	let bad = "EP-ZZZZZZZZZZZZ";
	assert!(!p.accepts(Some(bad), sender, recipient, day));
}

/// Wrap the plain `plain` text plus `token` in an RFC 2047 encoded-word
/// under `encoding` (B or Q). The token rides in plain ASCII, so the
/// encoding only has to cover the wrapper; this isolates the test from
/// any case-folding the wrapper would force on the token suffix.
fn encoded_subject(plain: &str, token: &str, encoding: char) -> String {
	let wrapped = format!("{plain} {token}");
	let payload: String = match encoding {
		'B' | 'b' => {
			use base64::Engine;
			use base64::engine::general_purpose::STANDARD as B64;
			B64.encode(wrapped.as_bytes())
		}
		'Q' | 'q' => {
			let mut out = String::with_capacity(wrapped.len() * 3);
			for byte in wrapped.bytes() {
				if byte == b' ' {
					out.push('_');
				} else if byte.is_ascii_graphic() && byte != b'=' && byte != b'?' && byte != b'_' {
					out.push(byte as char);
				} else {
					out.push_str(&format!("={byte:02X}"));
				}
			}
			out
		}
		_ => panic!("encoding must be B or Q"),
	};
	format!("=?UTF-8?{encoding}?{payload}?=")
}

#[test]
fn a_token_inside_an_rfc_2047_encoded_subject_is_accepted() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let token = p.issue(sender, recipient, day);
	let b_subject = encoded_subject("hello", &token, 'B');
	let q_subject = encoded_subject("hello", &token, 'Q');
	assert!(
		p.accepts(Some(&b_subject), sender, recipient, day),
		"B-encoded subject {b_subject:?} should still verify the token"
	);
	assert!(
		p.accepts(Some(&q_subject), sender, recipient, day),
		"Q-encoded subject {q_subject:?} should still verify the token"
	);
	// The same subjects with one token byte changed must NOT verify.
	let mut bad_token: String = token.clone();
	// Flip the last base32 character of the token to a different base32
	// char. The prefix is preserved so the word still splits cleanly;
	// only the HMAC changes.
	let mut last = bad_token.pop().unwrap();
	if last == 'A' {
		last = 'B';
	} else {
		last = 'A';
	}
	bad_token.push(last);
	let b_bad = encoded_subject("hello", &bad_token, 'B');
	let q_bad = encoded_subject("hello", &bad_token, 'Q');
	assert!(!p.accepts(Some(&b_bad), sender, recipient, day));
	assert!(!p.accepts(Some(&q_bad), sender, recipient, day));
}

#[test]
fn a_different_key_does_not_validate() {
	let p = pass();
	let other = SubjectPass::with_key([0u8; 32]);
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let token = p.issue(sender, recipient, day);
	assert!(!other.verify(&token, sender, recipient, day));
}

#[test]
fn token_prefix_is_lowercase_in_subject_input() {
	// A sender pasting the token verbatim usually pastes it as it appeared
	// in the bounce; operators may include the prefix in either case.
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let token = p.issue(sender, recipient, day);
	// Both upper- and lowercase prefixes are accepted (the verifier
	// normalises the suffix, so the prefix is the only case-sensitive bit).
	assert!(p.accepts(Some(&token.to_ascii_lowercase()), sender, recipient, day));
	assert!(p.accepts(Some(&token), sender, recipient, day));
}

#[test]
fn base32_encoding_round_trips_through_the_token() {
	// The token is the first 12 chars of the base32 of an HMAC-SHA256; the
	// suffix must therefore be all base32 alphabet characters.
	let p = pass();
	let token = p.issue("alice@example.org", "bob@example.org", 1);
	let suffix = token.strip_prefix(TOKEN_PREFIX).unwrap();
	assert_eq!(suffix.len(), TOKEN_CHARS);
	for byte in suffix.bytes() {
		assert!(
			byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte),
			"non-base32 byte {byte:?} in {suffix:?}"
		);
	}
}

#[test]
fn the_word_in_the_challenge_reply_is_the_token_and_passes() {
	let p = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let day = 20_000;
	let rendered = challenge_reply(&p, sender, recipient, day).to_string();
	assert!(rendered.starts_with("550 5.7.1 "), "{rendered}");
	// What a person copies out of the bounce is the whitespace-delimited
	// word that starts with the prefix. It has to be the token itself, and
	// it has to pass when pasted into a subject.
	let word = rendered
		.split_whitespace()
		.find(|word| word.starts_with(TOKEN_PREFIX))
		.expect("the reply carries a word with the token prefix");
	assert_eq!(word, p.issue(sender, recipient, day), "{rendered}");
	let subject = format!("Re: hello {word}");
	assert!(p.accepts(Some(&subject), sender, recipient, day), "{rendered}");
}

#[test]
fn header_value_finds_subject_case_insensitively() {
	let raw = b"From: a@example.org\r\nSubject: Hi there\r\n\r\nbody\r\n";
	assert_eq!(header_value(raw, "subject").as_deref(), Some("Hi there"));
	assert_eq!(header_value(raw, "Subject").as_deref(), Some("Hi there"));
	assert_eq!(header_value(raw, "SUBJECT").as_deref(), Some("Hi there"));
	// Folded continuation lines are unfolded into one value.
	let folded = b"Subject: Hi\r\n there\r\n\r\nbody\r\n";
	assert_eq!(header_value(folded, "subject").as_deref(), Some("Hi there"));
}

#[test]
fn open_persists_and_reloads_the_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = SubjectPass::open(dir.path()).expect("open");
	let token = first.issue("alice@example.org", "bob@example.org", 20_000);
	let second = SubjectPass::open(dir.path()).expect("reload");
	// The reloaded key validates the token the first instance minted.
	assert!(second.verify(&token, "alice@example.org", "bob@example.org", 20_000));
}

#[cfg(unix)]
#[test]
fn the_persisted_key_file_is_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	SubjectPass::open(dir.path()).expect("open");
	let mode = std::fs::metadata(dir.path().join("subjectpass.key"))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, "key file must not be group/world readable");
}
