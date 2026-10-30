//! The reserved namespace read the way the readers read it. A third review
//! (2026-10-15) found that the submission strip, the deduplication and the
//! lookup each read a field name narrower than at least one of the three
//! readers we support: mail-parser 0.11 folded a leading `:` away, and DKIM and
//! ARC-AMS fold trailing whitespace of any code point `char::is_whitespace`
//! knows. A client could therefore deliver a claim of ours, or a second copy
//! of a field, under a name one of those readers calls ours.
//!
//! Each test below states first which reader calls the spelling ours, so a
//! future parser that stopped folding it would have to prove the new reading
//! safe rather than pass by having nothing to match.

use super::*;

/// A submission whose header block carries `headers` verbatim.
fn with_headers(headers: &str) -> AcceptedMessage {
	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	message.data =
		format!("From: Sender <alice@example.org>\r\nSubject: hello\r\n{headers}\r\nbody\r\n")
			.into_bytes();
	message
}

/// The header names mail-parser reads out of `data`.
fn mail_parser_names(data: &[u8]) -> Vec<String> {
	mail_parser::MessageParser::default()
		.parse(data)
		.expect("the message parses")
		.headers()
		.iter()
		.map(|header| header.name().to_string())
		.collect()
}

#[test]
fn a_leading_colon_stays_distinct_and_dkim_still_folds_a_trailing_nbsp() {
	// 1.0 keeps the leading colon as part of an unknown name.
	let raw = b":X-Epistle-Attachment-Warning: forged\r\n\r\n".to_vec();
	assert_eq!(
		mail_parser_names(&raw),
		vec![":X-Epistle-Attachment-Warning".to_string()]
	);
	// DKIM and ARC-AMS apply `name.trim_end()` to each header, so a name
	// ending in NBSP is the marker itself to both of them. mail-parser keeps
	// the NBSP in the name, which is the half of the reading the strip has to
	// cover on its own.
	let raw = "X-Epistle\u{00A0}: forged\r\n\r\n".as_bytes().to_vec();
	assert!(
		!mail_parser_names(&raw)
			.iter()
			.any(|name| name == "X-Epistle"),
		"mail-parser is expected to keep the trailing whitespace in the name"
	);
	for (reader, names) in [
		("DKIM", crate::dkim::header_names(&raw)),
		("ARC", crate::arc::header_names(&raw)),
	] {
		assert_eq!(
			names,
			vec!["X-Epistle".to_string()],
			"{reader} must fold the trailing whitespace"
		);
	}
}

#[test]
fn a_field_under_a_readers_our_namespace_is_refused_before_it_reaches_a_receiver() {
	let mut message = with_headers(
		":X-Epistle-Attachment-Warning: forged\r\n\
		 \tcontinuation of the forged warning\r\n\
		 X-Epistle\u{00A0}: forged\r\n\
		 X-Epistlefoo: theirs\r\n",
	);
	let before = message.data.clone();
	let directory = directory();
	let refusal = apply(
		&mut message,
		MailClass::Personal,
		&Policy {
			x_epistle: true,
			..policy()
		},
		Some(&directory.current()),
	)
	.expect_err("malformed field name");
	assert_eq!(refusal, MarketingRefusal::MalformedHeaderLine);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}

#[test]
fn two_copies_the_readers_fold_into_one_name_are_refused() {
	let mut message = with_headers(
		"List-Unsubscribe: <https://example.org/u/1>\r\n\
		 List-Unsubscribe\u{00A0}: <https://example.org/u/2>\r\n",
	);
	let before = message.data.clone();
	let directory = directory();
	let refusal = apply(
		&mut message,
		MailClass::Personal,
		&policy(),
		Some(&directory.current()),
	)
	.expect_err("malformed field name");
	assert_eq!(refusal, MarketingRefusal::AmbiguousHeaderName);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}

#[test]
fn an_authentication_results_under_a_leading_colon_is_refused() {
	let mut message = with_headers(":Authentication-Results: forged.example; dkim=pass\r\n");
	let before = message.data.clone();
	let directory = directory();
	let refusal = apply(
		&mut message,
		MailClass::Personal,
		&policy(),
		Some(&directory.current()),
	)
	.expect_err("malformed field name");
	assert_eq!(refusal, MarketingRefusal::MalformedHeaderLine);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}
