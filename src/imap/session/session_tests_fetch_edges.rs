use super::fetch_envelope::{PLAIN, exact, selected};
use super::fetch_sections::literal;
use super::fetch_structure::{ALTERNATIVE, MIXED, nested};

#[test]
fn fetch_edges_deep_paths_and_encapsulated_fields() {
	let mut raw = b"Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\n".to_vec();
	raw.extend_from_slice(ALTERNATIVE);
	raw.extend_from_slice(b"\r\n--o\r\nContent-Type: message/rfc822\r\n\r\n");
	raw.extend_from_slice(PLAIN);
	raw.extend_from_slice(b"\r\n--o--\r\n");
	let (_dir, mut session) = selected(&raw);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[1.2])",
		&literal("BODY[1.2]", b"<b>x</b>", ""),
		"deep numeric sections must follow the MIME tree",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[2.HEADER])",
		&literal("BODY[2.HEADER]", &PLAIN[..PLAIN.len() - 7], ""),
		"2.HEADER must return the encapsulated message headers",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[2.HEADER.FIELDS (SUBJECT)]<2.5>)",
		&literal("BODY[2.HEADER.FIELDS (SUBJECT)]<2>", b"bject", ""),
		"header partials must apply after field filtering",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.PEEK[2.1])",
		&literal("BINARY[2.1]", b"hello\r\n", ""),
		"BINARY must traverse encapsulated message parts",
	);
}

#[test]
fn fetch_edges_envelope_mime_fixtures() {
	let nested = nested();
	for raw in [ALTERNATIVE, MIXED, nested.as_slice()] {
		let (_dir, mut session) = selected(raw);
		exact(&mut session, "f FETCH 1 (ENVELOPE)", b"* 1 FETCH (ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL))\r\nf OK FETCH completed\r\n", "MIME-only messages must return ten absent envelope fields");
	}
}

#[test]
fn fetch_edges_long_literal_and_encoded_structure() {
	let subject = "a".repeat(1025);
	let raw = format!("Subject: {subject}\r\n\r\nx");
	let (_dir, mut session) = selected(raw.as_bytes());
	let expected = format!(
		"* 1 FETCH (ENVELOPE (NIL {{1025}}\r\n{subject} NIL NIL NIL NIL NIL NIL NIL NIL))\r\nf OK FETCH completed\r\n"
	);
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		expected.as_bytes(),
		"long envelope strings must use counted literals",
	);
	let (_dir2, mut encoded) = selected(
		b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\nFrom: Alice <a@b>\r\nTo: Team: Bob <b@c>;\r\n\r\nx",
	);
	exact(&mut encoded, "f FETCH 1 (BODYSTRUCTURE BODY)", b"* 1 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 1 0 NIL NIL NIL NIL) BODY (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 1 0))\r\nf OK FETCH completed\r\n", "encoded envelope headers must leave MIME body counts unchanged");

	exact(
		&mut encoded,
		"f FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])",
		&literal(
			"BODY[HEADER.FIELDS (SUBJECT)]",
			b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\n\r\n",
			"",
		),
		"BODY header filtering must preserve RFC 2047 subject words verbatim",
	);
}

#[test]
fn fetch_edges_binary_literal8_and_invalid_selectors() {
	let (_dir, mut session) = selected(
		b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.PEEK[1])",
		b"* 1 FETCH (BINARY[1] ~{3}\r\n\x00\x01\xff)\r\nf OK FETCH completed\r\n",
		"BINARY containing NUL must use literal8 and preserve octets",
	);
	for item in [
		"BODY[0]",
		"BODY.PEEK[1.]",
		"BODY.PEEK[1..2]",
		"BODY[TEXT]<0.0>",
		"BODY[TEXT]<-1.2>",
		"BODY[TEXT]<1.9999999999999999999999999>",
		"BODY[HEADER.FIELDS ()]",
		"BINARY[HEADER]",
		"BINARY.SIZE[1]<0.1>",
		"BODY[MIME]",
	] {
		exact(
			&mut session,
			&format!("f FETCH 1 ({item})"),
			b"f BAD invalid arguments\r\n",
			"malformed section selectors must receive tagged BAD",
		);
	}
}

#[test]
fn fetch_edges_empty_message_whole_peek() {
	let (_dir, mut session) = selected(b"");
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[])",
		&literal("BODY[]", b"", ""),
		"an empty whole-message PEEK must return a zero length literal",
	);
}

#[test]
fn fetch_edges_envelope_non_utf8_display_name() {
	let (_dir, mut session) = selected(b"From: Andr\xe9 <a@b>\r\n\r\nx");
	let addr = b"(({5}\r\nAndr\xe9 NIL \"a\" \"b\"))";
	let mut expected = b"* 1 FETCH (ENVELOPE (NIL NIL ".to_vec();
	for i in 0..3 {
		if i > 0 {
			expected.push(b' ');
		}
		expected.extend_from_slice(addr);
	}
	expected.extend_from_slice(b" NIL NIL NIL NIL NIL))\r\nf OK FETCH completed\r\n");
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		&expected,
		"ENVELOPE must preserve raw non-UTF8 display-name octets",
	);
}
