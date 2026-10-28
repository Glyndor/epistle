//! Sections that end where their message ends: BINARY[] of a multipart
//! message, and TEXT of an encapsulated message with an epilogue.

use super::fetch_envelope::{exact, selected};
use super::fetch_sections::literal;

const MIXED: &[u8] = b"From: user@domain.org\r\n\
Content-Type: multipart/mixed; boundary=\"foo\"\r\n\
\r\n\
Root MIME prologue\r\n\
\r\n\
--foo\r\n\
Content-Type: text/x-myown; charset=us-ascii\r\n\
\r\n\
hello\r\n\
\r\n\
--foo--\r\n\
Root MIME epilogue\r\n";

const ENCAPSULATED: &[u8] = b"From: user@domain.org\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
From: sub@domain.org\r\n\
Content-Type: multipart/digest; boundary=\"foo\"\r\n\
\r\n\
prologue\r\n\
\r\n\
--foo \r\n\
\r\n\
From: m1@example.com\r\n\
\r\n\
m1 body\r\n\
\r\n\
--foo--\r\n\
\r\n\
epilogue\r\n";

#[test]
fn binary_of_the_whole_message_is_the_message() {
	// RFC 3516 §4.2: BINARY[] is the entire message, decoded; a multipart
	// root has nothing to decode, so it is the message as stored.
	let (_dir, mut session) = selected(MIXED);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.PEEK[])",
		&literal("BINARY[]", MIXED, ""),
		"BINARY[] must hold the header and the whole body",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.SIZE[])",
		format!(
			"* 1 FETCH (BINARY.SIZE[] {})\r\nf OK FETCH completed\r\n",
			MIXED.len()
		)
		.as_bytes(),
		"BINARY.SIZE[] must count the whole message",
	);
}

#[test]
fn text_of_an_encapsulated_message_keeps_its_epilogue() {
	let (_dir, mut session) = selected(ENCAPSULATED);
	let start = ENCAPSULATED
		.windows(8)
		.position(|w| w == b"prologue")
		.unwrap();
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[1.TEXT])",
		&literal("BODY[1.TEXT]", &ENCAPSULATED[start..], ""),
		"TEXT of a message/rfc822 part must run to the end of that message",
	);
}
