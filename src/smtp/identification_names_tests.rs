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
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::{AliasSpec, Directory};
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

/// A submission from a list address whose client wrote the spaced spellings
/// leaves the list's own fields, one of each, and no claim about a check
/// this hop never made.
#[test]
fn a_submission_with_spaced_names_carries_the_lists_own() {
	let directory = DirectoryHandle::new(Directory::default().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: Some("team.example.org".to_string()),
		},
	)]));
	let mut message = AcceptedMessage {
		reverse_path: "team@example.org".into(),
		recipients: vec!["bob@example.org".to_string()],
		data: carrying(&spellings(), "<forged.example>"),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	apply(
		&mut message,
		MailClass::Personal,
		&Policy::default(),
		Some(&directory.current()),
	);
	let raw = &message.data;
	assert_eq!(reader_sees(raw, "Authentication-Results"), 0);
	assert_eq!(reader_sees(raw, "List-ID"), 1, "two List-Id");
	assert_eq!(reader_sees(raw, "List-Post"), 1, "two List-Post");
	assert_eq!(
		header_values(raw, "list-id"),
		["<team.example.org>"],
		"the list's own identifier"
	);
}
