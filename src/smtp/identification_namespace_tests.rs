//! The reserved namespace read the way the readers read it. A third review
//! (2026-10-15) found that the submission strip, the deduplication and the
//! lookup each read a field name narrower than at least one of the three
//! readers we support: mail-parser folds a leading `:` away, and DKIM and
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

/// The header names each reader we support takes out of `data`, so a leftover
/// claim is looked for in every one of them rather than in one of ours.
fn names_every_reader_sees(data: &[u8]) -> Vec<Vec<String>> {
	vec![
		mail_parser_names(data),
		crate::dkim::header_names(data),
		crate::arc::header_names(data),
	]
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

/// Whether a reader calls `name` the reserved marker or a name under it.
fn is_our_namespace(name: &str) -> bool {
	let name = name.to_ascii_lowercase();
	name == "x-epistle" || name.starts_with("x-epistle-")
}

#[test]
fn a_leading_colon_and_a_trailing_nbsp_are_the_names_the_readers_call_ours() {
	// mail-parser 0.11.9 (`parse_header_name`) folds the leading `:` while
	// the name has not started, so it reads the field under the name every
	// other reader would read after the fold too.
	let raw = b":X-Epistle-Attachment-Warning: forged\r\n\r\n".to_vec();
	assert_eq!(
		mail_parser_names(&raw),
		vec!["X-Epistle-Attachment-Warning".to_string()],
		"mail-parser must fold the leading colon"
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
fn a_field_the_readers_call_our_namespace_never_reaches_a_receiver() {
	// The two spellings of the report: a leading colon with a folded
	// continuation, and a name whose trailing whitespace only `trim_end()`
	// folds. A name that merely starts like ours is the client's and stays.
	let mut message = with_headers(
		":X-Epistle-Attachment-Warning: forged\r\n\
		 \tcontinuation of the forged warning\r\n\
		 X-Epistle\u{00A0}: forged\r\n\
		 X-Epistlefoo: theirs\r\n",
	);
	apply_to(
		&mut message,
		MailClass::Personal,
		&Policy {
			x_epistle: true,
			..policy()
		},
	);
	let text = String::from_utf8_lossy(&message.data);
	assert!(
		!text.contains("forged") && !text.contains("continuation of"),
		"a claim of ours survived under a spelling a reader folds: {text}"
	);
	assert_eq!(
		values(&message, "x-epistle"),
		vec![X_EPISTLE_VALUE.to_string()],
		"the server's own marker is not the only copy: {text}"
	);
	assert_eq!(
		values(&message, "x-epistlefoo"),
		vec!["theirs".to_string()],
		"a name outside the namespace is the client's and stays: {text}"
	);
	for names in names_every_reader_sees(&message.data) {
		let ours: Vec<&String> = names.iter().filter(|name| is_our_namespace(name)).collect();
		assert_eq!(
			ours.len(),
			1,
			"a claim of ours a reader still sees: {names:?}"
		);
		assert_eq!(ours[0], "X-Epistle", "not the server's own copy: {names:?}");
	}
}

#[test]
fn two_copies_the_readers_fold_into_one_name_are_reduced_to_one() {
	let mut message = with_headers(
		"List-Unsubscribe: <https://example.org/u/1>\r\n\
		 List-Unsubscribe\u{00A0}: <https://example.org/u/2>\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	let text = String::from_utf8_lossy(&message.data);
	assert!(
		!text.contains("/u/2"),
		"the second copy stayed, under a name a receiver folds: {text}"
	);
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<https://example.org/u/1>".to_string()],
		"the sender wrote two, so a receiver is left to guess which to act on"
	);
	assert_eq!(
		crate::dkim::header_names(&message.data)
			.iter()
			.filter(|name| name.eq_ignore_ascii_case("list-unsubscribe"))
			.count(),
		1,
		"the reader that folds the trailing whitespace sees two fields: {text}"
	);
}

#[test]
fn an_authentication_results_under_a_leading_colon_is_removed_from_a_submission() {
	// A submission had no check of ours to report, so the field goes whatever
	// the client called it.
	let mut message = with_headers(":Authentication-Results: forged.example; dkim=pass\r\n");
	apply_to(&mut message, MailClass::Personal, &policy());
	assert!(
		values(&message, "authentication-results").is_empty()
			&& !String::from_utf8_lossy(&message.data).contains("forged.example"),
		"a claim about a hop that did not take place survived: {}",
		String::from_utf8_lossy(&message.data)
	);
}
