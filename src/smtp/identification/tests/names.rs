//! The identity of a header name: the same for the strip, the deduplication
//! and the lookup, and the same a reader downstream reads.
//!
//! mail-parser 0.11.9 drops every ASCII whitespace byte out of a name before
//! it looks the name up in its table of the known ones (`parse_header_name`),
//! so `List -Id` is `List-Id` and `Authenti cation-Results` is
//! `Authentication-Results` to it. Comparing the bytes of a name as they
//! stand gave the three operations an identity narrower than the reader's: a
//! submission could carry two `List-Unsubscribe` under two spellings and a
//! `Authentication-Results` about a check this hop never made, in a spelling
//! the reader resolves to the field of that name.
//!
//! Every assertion below counts with mail-parser rather than with
//! `header_values`, so the comparator under test is never the oracle of its
//! own test.

use super::*;
use crate::smtp::trace::{header_values, keep_first_of_each_in_place, strip_headers_in_place};

/// The headers this module acts on, each with a spelling that carries
/// whitespace inside its name: the header a reader sees, and the name as a
/// client may write it. The first is the canonical name mail-parser itself
/// reports, which for the list identifier is `List-ID` with both letters in
/// capitals.
const SPACED: &[(&str, &str)] = &[
	("Authentication-Results", "Authenti cation-Results"),
	("List-ID", "List -Id"),
	("List-Post", "List -Post"),
	("List-Unsubscribe", "List -Unsubscribe"),
	("List-Unsubscribe-Post", "List -Unsubscribe-Post"),
];

/// The spellings, in the order they are declared.
fn spellings() -> Vec<&'static str> {
	SPACED.iter().map(|(_, spaced)| *spaced).collect()
}

/// A message with one field per name in `names`, each carrying `value`.
fn carrying(names: &[&str], value: &str) -> Vec<u8> {
	let mut raw = String::from("From: Sender <alice@example.org>\r\n");
	for name in names {
		raw.push_str(&format!("{name}: {value}\r\n"));
	}
	raw.push_str("Subject: hello\r\n\r\nbody\r\n");
	raw.into_bytes()
}

/// How many fields of the header `canonical` a reader finds in `raw`, counted
/// through mail-parser rather than through our own lookup.
fn reader_sees(raw: &[u8], canonical: &str) -> usize {
	mail_parser::MessageParser::default()
		.parse_headers(raw)
		.expect("a header block")
		.headers()
		.iter()
		.filter(|header| header.name() == canonical)
		.count()
}

/// Every spelling above resolves to the header it names, which is what the
/// three tests below stand on: without it a green result would prove nothing.
#[test]
fn a_reader_resolves_every_spaced_spelling_to_its_header() {
	let raw = carrying(&spellings(), "forged.example; dkim=pass");
	for (canonical, spaced) in SPACED {
		assert_eq!(
			reader_sees(&raw, canonical),
			1,
			"{spaced} is not the {canonical} a reader reads"
		);
	}
}

/// The strip acts on the name a reader reads, so a spelling that reader folds
/// does not survive it.
#[test]
fn the_strip_removes_every_spaced_spelling() {
	let mut raw = carrying(&spellings(), "forged.example; dkim=pass");
	let names: Vec<&str> = SPACED.iter().map(|(canonical, _)| *canonical).collect();
	strip_headers_in_place(&mut raw, &names);
	for (canonical, spaced) in SPACED {
		assert_eq!(
			reader_sees(&raw, canonical),
			0,
			"a reader still finds {canonical}, written {spaced}"
		);
	}
}

/// Two fields of one name are two copies however each is spelled: the
/// deduplication keeps the first, and the lookup finds the one it kept.
#[test]
fn the_deduplication_collapses_two_spellings_of_one_name() {
	let mut raw = carrying(
		&[
			"List -Unsubscribe",
			"List-Unsubscribe",
			"List -Unsubscribe-Post",
			"List-Unsubscribe-Post",
		],
		"<https://example.org/u/one>",
	);
	keep_first_of_each_in_place(&mut raw, &["List-Unsubscribe", "List-Unsubscribe-Post"]);
	assert_eq!(reader_sees(&raw, "List-Unsubscribe"), 1, "two unsubscribes");
	assert_eq!(reader_sees(&raw, "List-Unsubscribe-Post"), 1, "two posts");
	assert_eq!(
		header_values(&raw, "list-unsubscribe"),
		["<https://example.org/u/one>"],
		"the copy the deduplication kept"
	);
}

/// A submission with any spaced field name is refused before the server
/// changes a header.
#[test]
fn a_submission_with_spaced_names_is_refused() {
	let mut message = submitted(carrying(&spellings(), "<forged.example>"));
	let before = message.data.clone();
	let refusal = apply(&mut message, MailClass::Personal, &Policy::default(), None)
		.expect_err("spaced names");
	assert_eq!(
		refusal,
		crate::evidence::marketing::MarketingRefusal::AmbiguousHeaderName
	);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}

/// A submission with the given raw bytes.
fn submitted(data: Vec<u8>) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".to_string()],
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

/// A field name with ASCII whitespace inside it has more than one meaning
/// to the server and a reader. The submission is refused before any header
/// is changed.
#[test]
fn a_field_name_with_ascii_whitespace_inside_is_refused() {
	for name in [
		"List -Unsubscribe",
		"List\t-Unsubscribe",
		"List\u{0b}-Unsubscribe",
	] {
		let mut message = submitted(carrying(&[name], "<https://example.org/u>"));
		let before = message.data.clone();
		let refusal =
			apply(&mut message, MailClass::Personal, &Policy::default(), None).expect_err(name);
		assert_eq!(
			refusal,
			crate::evidence::marketing::MarketingRefusal::AmbiguousHeaderName,
			"{name:?}"
		);
		assert_eq!(message.data, before, "{name:?} changed before the refusal");
	}
}

/// Trailing whitespace before the colon is the obsolete syntax readers
/// still accept. It does not make the field name ambiguous.
#[test]
fn a_trailing_space_before_the_colon_is_accepted() {
	let mut message =
		submitted(b"From : alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec());
	apply(&mut message, MailClass::Personal, &Policy::default(), None)
		.expect("ordinary submission");
	let text = String::from_utf8_lossy(&message.data);
	assert!(text.contains("From : alice@example.org\r\n"), "{text}");
}

/// A carriage return that is not followed by a line feed makes the header
/// framing ambiguous. The submission is refused before any header changes.
#[test]
fn a_bare_carriage_return_in_the_header_block_is_refused() {
	let mut message = submitted(
		b"From: alice@example.org\r\n\rX-Epistle: forged\r\nSubject: s\r\n\r\nbody\r\n".to_vec(),
	);
	let before = message.data.clone();
	let refusal =
		apply(&mut message, MailClass::Personal, &Policy::default(), None).expect_err("bare CR");
	assert_eq!(
		refusal,
		crate::evidence::marketing::MarketingRefusal::AmbiguousHeaderFraming
	);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}

/// A CRCRLF boundary is ambiguous even though a reader accepts it. The
/// body after it is left untouched because the whole submission is refused.
#[test]
fn a_crcrlf_boundary_is_refused_before_the_body_is_changed() {
	let mut message = submitted(
		b"From: alice@example.org\r\nSubject: s\r\n\r\r\n\
		  List -Unsubscribe: this is body text\r\n\
		  X-Epistle: body text\r\n\
		  Authentication-Results: body text\r\n"
			.to_vec(),
	);
	let before = message.data.clone();
	let refusal =
		apply(&mut message, MailClass::Personal, &Policy::default(), None).expect_err("CRCRLF");
	assert_eq!(
		refusal,
		crate::evidence::marketing::MarketingRefusal::AmbiguousHeaderFraming
	);
	assert_eq!(message.data, before, "the body changed before the refusal");
}

/// A second From whose name carries whitespace is ambiguous. It is refused
/// before the author check, so it cannot become a second ordinary From.
#[test]
fn a_second_from_with_whitespace_inside_is_refused_before_signing() {
	let mut message = submitted(
		b"From: alice@example.org\r\nFr om: victim@elsewhere.example\r\n\
		  Subject: s\r\n\r\nbody\r\n"
			.to_vec(),
	);
	let before = message.data.clone();
	let refusal = apply(&mut message, MailClass::Personal, &Policy::default(), None)
		.expect_err("spaced From");
	assert_eq!(
		refusal,
		crate::evidence::marketing::MarketingRefusal::AmbiguousHeaderName
	);
	assert_eq!(
		message.data, before,
		"the message changed before the refusal"
	);
}

/// A field-looking line after the real blank line is body text. It is
/// neither rejected nor changed.
#[test]
fn a_list_unsubscribe_after_the_real_blank_line_is_left_in_the_body() {
	let body = b"List -Unsubscribe: texto\r\n";
	let mut data = b"From: alice@example.org\r\nSubject: s\r\n\r\n".to_vec();
	data.extend_from_slice(body);
	let mut message = submitted(data);
	apply(&mut message, MailClass::Personal, &Policy::default(), None)
		.expect("ordinary submission");
	assert!(message.data.ends_with(body), "the body changed");
	assert!(
		header_values(&message.data, "list-unsubscribe").is_empty(),
		"the body line became a header"
	);
}

/// A signer and the DNS that publishes its key, to check what it signs.
fn signer_and_dns() -> (crate::dkim::Signer, crate::dkim::test_support::KeyDns) {
	use std::io::Write;
	let (pem, record) = crate::dkim::generate_key().expect("generate key");
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(pem.as_bytes()).expect("write key");
	let signer = crate::dkim::Signer::load("sel", file.path()).expect("load key");
	let records =
		std::collections::HashMap::from([("sel._domainkey.example.org".to_string(), vec![record])]);
	(signer, crate::dkim::test_support::KeyDns(records))
}

/// The ordinary one-click pair is signed. A URL changed after signing is
/// refused by the signature.
#[tokio::test]
async fn an_ordinary_unsubscribe_pair_is_signed_and_a_changed_url_is_refused() {
	let mut message = submitted(
		b"From: alice@example.org\r\nList-Unsubscribe: <https://example.org/one>\r\n\
		  List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\nbody\r\n"
			.to_vec(),
	);
	apply(&mut message, MailClass::Personal, &Policy::default(), None)
		.expect("ordinary submission");
	let raw = String::from_utf8(message.data.clone()).expect("utf8");
	let (signer, dns) = signer_and_dns();
	let signature = signer.sign("example.org", raw.as_bytes()).expect("signs");
	let signed = format!("{signature}{raw}");
	let results = crate::dkim::verify_message(&dns, signed.as_bytes()).await;
	assert_eq!(
		results[0].outcome,
		crate::dkim::DkimOutcome::Pass,
		"the message does not verify: {results:?}"
	);
	let changed = raw.replace("/one>", "/two>");
	assert_ne!(changed, raw, "the URL did not change");
	let signed = format!("{signature}{changed}");
	let results = crate::dkim::verify_message(&dns, signed.as_bytes()).await;
	assert_eq!(
		results[0].outcome,
		crate::dkim::DkimOutcome::Fail,
		"a changed URL passed the signature: {results:?}"
	);
}
