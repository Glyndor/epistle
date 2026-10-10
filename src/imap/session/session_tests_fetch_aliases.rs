use super::fetch_envelope::{PLAIN, SIMPLE, exact, selected};
use super::fetch_sections::literal;
use super::fetch_structure::{ALTERNATIVE, MIXED, TEXT, nested};

const DATE: &str = "\" 2-Jan-1970 00:00:00 +0000\"";

#[test]
fn fetch_aliases_header_text_and_rfc822_in_rev1_and_rev2() {
	for rev2 in [false, true] {
		let (_dir, mut session) = selected(PLAIN);
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		exact(
			&mut session,
			"f FETCH 1 (RFC822.HEADER)",
			&literal("RFC822.HEADER", &PLAIN[..PLAIN.len() - 7], ""),
			"RFC822.HEADER must return exact headers without setting Seen",
		);
		exact(
			&mut session,
			"f FETCH 1 (FLAGS)",
			b"* 1 FETCH (FLAGS ())\r\nf OK FETCH completed\r\n",
			"RFC822.HEADER must keep Seen clear",
		);
		exact(
			&mut session,
			"f FETCH 1 (RFC822.TEXT)",
			&literal("RFC822.TEXT", b"hello\r\n", " FLAGS (\\Seen)"),
			"RFC822.TEXT must return exact text and set Seen",
		);
		exact(
			&mut session,
			"f FETCH 1 (RFC822)",
			&literal("RFC822", PLAIN, ""),
			"RFC822 must use its own response label",
		);
	}
}

#[test]
fn fetch_aliases_macros_all_fast_full() {
	let (_dir, mut session) = selected(PLAIN);
	let fast = format!("FLAGS () INTERNALDATE {DATE} RFC822.SIZE {}", PLAIN.len());
	exact(
		&mut session,
		"f FETCH 1 FAST",
		format!("* 1 FETCH ({fast})\r\nf OK FETCH completed\r\n").as_bytes(),
		"FAST must return FLAGS INTERNALDATE and RFC822.SIZE",
	);
	exact(
		&mut session,
		"f FETCH 1 ALL",
		format!("* 1 FETCH ({fast} ENVELOPE {SIMPLE})\r\nf OK FETCH completed\r\n").as_bytes(),
		"ALL must include the exact ENVELOPE",
	);
	exact(
		&mut session,
		"f FETCH 1 FULL",
		format!("* 1 FETCH ({fast} ENVELOPE {SIMPLE} BODY {TEXT})\r\nf OK FETCH completed\r\n")
			.as_bytes(),
		"FULL must include the non-extensible BODY",
	);
	exact(
		&mut session,
		"f FETCH 1 (FLAGS)",
		b"* 1 FETCH (FLAGS ())\r\nf OK FETCH completed\r\n",
		"FETCH macros must leave Seen clear",
	);
}

#[test]
fn fetch_aliases_uid_and_changed_since() {
	let (_dir, mut session) = selected(PLAIN);
	let mut expected = literal(
		"RFC822.HEADER",
		&PLAIN[..PLAIN.len() - 7],
		" UID 1 MODSEQ (1)",
	);
	exact(
		&mut session,
		"f UID FETCH 1:* (RFC822.HEADER) (CHANGEDSINCE 0)",
		&expected,
		"UID RFC822.HEADER must preserve CHANGEDSINCE and identifiers",
	);
	exact(
		&mut session,
		"f UID FETCH 1:* (RFC822.HEADER) (CHANGEDSINCE 1)",
		b"f OK FETCH completed\r\n",
		"CHANGEDSINCE must suppress unchanged alias data",
	);
	expected = literal(
		"RFC822.TEXT",
		b"hello\r\n",
		" UID 1 MODSEQ (2) FLAGS (\\Seen)",
	);
	exact(
		&mut session,
		"f UID FETCH 1:* (RFC822.TEXT) (CHANGEDSINCE 0)",
		&expected,
		"UID RFC822.TEXT must report the Seen mod-sequence transition",
	);
}

#[test]
fn fetch_aliases_mime_fixtures_keep_raw_bytes() {
	let nested = nested();
	let encoded = b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\nFrom: Alice <alice@example.org>\r\nTo: Friends: bob@example.net;\r\n\r\nencoded\r\n";
	for raw in [ALTERNATIVE, MIXED, nested.as_slice(), encoded] {
		let (_dir, mut session) = selected(raw);
		let body_offset = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
		exact(
			&mut session,
			"f FETCH 1 (RFC822.HEADER)",
			&literal("RFC822.HEADER", &raw[..body_offset], ""),
			"RFC822.HEADER must preserve MIME and encoded headers verbatim",
		);
		exact(
			&mut session,
			"f FETCH 1 (RFC822.TEXT)",
			&literal("RFC822.TEXT", &raw[body_offset..], " FLAGS (\\Seen)"),
			"RFC822.TEXT must preserve the complete encoded MIME body",
		);
	}
}

#[test]
fn fetch_aliases_text_only() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (RFC822.TEXT)",
		&literal("RFC822.TEXT", b"hello\r\n", " FLAGS (\\Seen)"),
		"RFC822.TEXT alone must return text and updated FLAGS",
	);
}

#[test]
fn fetch_aliases_rfc822_only() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (RFC822)",
		&literal("RFC822", PLAIN, " FLAGS (\\Seen)"),
		"RFC822 alone must return its label and updated FLAGS",
	);
}

#[test]
fn fetch_aliases_full_only() {
	let (_dir, mut session) = selected(PLAIN);
	let full = format!(
		"FLAGS () INTERNALDATE {DATE} RFC822.SIZE {} ENVELOPE {SIMPLE} BODY {TEXT}",
		PLAIN.len()
	);
	exact(
		&mut session,
		"f FETCH 1 FULL",
		format!("* 1 FETCH ({full})\r\nf OK FETCH completed\r\n").as_bytes(),
		"FULL alone must include the exact envelope and non-extensible body",
	);
}
