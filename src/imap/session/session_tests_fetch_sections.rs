use super::fetch_envelope::{PLAIN, exact, selected};
use super::fetch_structure::{ALTERNATIVE, MIXED, nested};

pub(super) fn literal(label: &str, data: &[u8], suffix: &str) -> Vec<u8> {
	let mut expected = format!("* 1 FETCH ({label} {{{}}}\r\n", data.len()).into_bytes();
	expected.extend_from_slice(data);
	expected.extend_from_slice(format!("{suffix})\r\nf OK FETCH completed\r\n").as_bytes());
	expected
}

#[test]
fn fetch_section_header_and_python_imaplib_fields() {
	let (_dir, mut session) = selected(PLAIN);
	let headers = &PLAIN[..PLAIN.len() - 7];
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[HEADER])",
		&literal("BODY[HEADER]", headers, ""),
		"HEADER must return original headers and the terminating blank line",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])",
		&literal(
			"BODY[HEADER.FIELDS (SUBJECT)]",
			b"Subject: hello\r\n\r\n",
			"",
		),
		"imaplib HEADER.FIELDS must return the exact subject header",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])",
		&literal(
			"BODY[HEADER.FIELDS (FROM SUBJECT)]",
			b"Subject: hello\r\nFrom: Alice <alice@example.org>\r\n\r\n",
			"",
		),
		"HEADER.FIELDS must preserve original order and header spelling",
	);
	exact(
		&mut session,
		"f FETCH 1 (FLAGS)",
		b"* 1 FETCH (FLAGS ())\r\nf OK FETCH completed\r\n",
		"PEEK header fetches must leave Seen clear",
	);
}

#[test]
fn fetch_section_fields_not_and_folding() {
	let raw = b"Subject: one\r\n\ttwo\r\nX-Test: first\r\nX-Test: second\r\nFrom: a@b\r\n\r\nbody";
	let (_dir, mut session) = selected(raw);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[HEADER.FIELDS.NOT (FROM)])",
		&literal(
			"BODY[HEADER.FIELDS.NOT (FROM)]",
			b"Subject: one\r\n\ttwo\r\nX-Test: first\r\nX-Test: second\r\n\r\n",
			"",
		),
		"HEADER.FIELDS.NOT must retain folded and duplicate headers",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[HEADER.FIELDS (MISSING)])",
		&literal("BODY[HEADER.FIELDS (MISSING)]", b"\r\n", ""),
		"an empty header selection must contain the terminating CRLF",
	);
}

#[test]
fn fetch_section_thunderbird_uid_listing_changed_since() {
	let (_dir, mut session) = selected(PLAIN);
	let fields = "FROM TO CC BCC SUBJECT DATE MESSAGE-ID PRIORITY X-PRIORITY REFERENCES NEWSGROUPS IN-REPLY-TO CONTENT-TYPE REPLY-TO";
	let command = "f UID FETCH 1:* (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To)]) (CHANGEDSINCE 0)";
	let headers = &PLAIN[..PLAIN.len() - 7];
	let mut expected = format!(
		"* 1 FETCH (UID 1 RFC822.SIZE {} FLAGS () BODY[HEADER.FIELDS ({fields})] {{{}}}\r\n",
		PLAIN.len(),
		headers.len()
	)
	.into_bytes();
	expected.extend_from_slice(headers);
	expected.extend_from_slice(b" MODSEQ (1))\r\nf OK FETCH completed\r\n");
	exact(
		&mut session,
		command,
		&expected,
		"Thunderbird UID listing must return exact header bytes with CHANGEDSINCE",
	);
}

#[test]
fn fetch_section_numbered_parts_mime_and_binary() {
	let (_dir, mut session) = selected(MIXED);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[2])",
		&literal("BODY[2]", b"aGVsbG8=", ""),
		"numbered BODY sections must return encoded attachment octets",
	);
	let mime = b"Content-Type: application/octet-stream; name=hello.bin\r\nContent-Disposition: attachment; filename=hello.bin\r\nContent-ID: <file@example.org>\r\nContent-Description: data\r\nContent-Transfer-Encoding: base64\r\n\r\n";
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[2.MIME])",
		&literal("BODY[2.MIME]", mime, ""),
		"MIME must return the part headers and terminating blank line",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.PEEK[2])",
		&literal("BINARY[2]", b"hello", ""),
		"BINARY must decode only the requested attachment",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY.SIZE[2])",
		b"* 1 FETCH (BINARY.SIZE[2] 5)\r\nf OK FETCH completed\r\n",
		"BINARY.SIZE must report decoded attachment octets",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[9])",
		b"* 1 FETCH (BODY[9] NIL)\r\nf OK FETCH completed\r\n",
		"missing BODY parts must return NIL",
	);
}

#[test]
fn fetch_section_alternative_and_nested_message() {
	let (_dir, mut session) = selected(ALTERNATIVE);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[2])",
		&literal("BODY[2]", b"<b>x</b>", ""),
		"alternative sections must select the requested representation",
	);
	let (_dir2, mut nested_session) = selected(&nested());
	exact(
		&mut nested_session,
		"f FETCH 1 (BODY.PEEK[1.HEADER])",
		&literal("BODY[1.HEADER]", &PLAIN[..PLAIN.len() - 7], ""),
		"message/rfc822 HEADER must select encapsulated headers",
	);
	exact(
		&mut nested_session,
		"f FETCH 1 (BODY.PEEK[1.TEXT])",
		&literal("BODY[1.TEXT]", b"hello\r\n", ""),
		"message/rfc822 TEXT must select encapsulated body",
	);
	exact(
		&mut nested_session,
		"f FETCH 1 (BODY.PEEK[1.1])",
		&literal("BODY[1.1]", b"hello\r\n", ""),
		"nested numeric sections must descend into message/rfc822",
	);
}

#[test]
fn fetch_section_partial_and_seen_persistence() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[TEXT]<1.3>)",
		&literal("BODY[TEXT]<1>", b"ell", ""),
		"partial BODY must return the requested octets and origin only",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY.PEEK[TEXT]<999.8>)",
		&literal("BODY[TEXT]<999>", b"", ""),
		"partial beyond the end must return a zero length literal",
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY[TEXT]<0.5>)",
		&literal("BODY[TEXT]<0>", b"hello", " FLAGS (\\Seen)"),
		"non-PEEK BODY must set Seen and include updated FLAGS",
	);
	session.command_line("s SELECT INBOX");
	exact(
		&mut session,
		"f FETCH 1 (FLAGS)",
		b"* 1 FETCH (FLAGS (\\Seen))\r\nf OK FETCH completed\r\n",
		"Seen set by FETCH must persist on reselection",
	);
}

#[test]
fn fetch_section_whole_message_seen_and_read_only() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (BODY[])",
		&literal("BODY[]", PLAIN, " FLAGS (\\Seen)"),
		"whole BODY must set Seen and include updated FLAGS",
	);
	session.command_line("f STORE 1 -FLAGS.SILENT (\\Seen)");
	session.command_line("s EXAMINE INBOX");
	exact(
		&mut session,
		"f FETCH 1 (BODY[TEXT])",
		&literal("BODY[TEXT]", b"hello\r\n", ""),
		"read-only BODY must return the body without setting Seen",
	);
	exact(
		&mut session,
		"f FETCH 1 (FLAGS)",
		b"* 1 FETCH (FLAGS ())\r\nf OK FETCH completed\r\n",
		"EXAMINE must keep Seen clear after BODY",
	);
}

#[test]
fn fetch_section_binary_partial_preserves_octets_and_seen() {
	let (_dir, mut session) = selected(b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9");
	exact(
		&mut session,
		"f FETCH 1 (BINARY.PEEK[1]<2.2>)",
		&literal("BINARY[1]<2>", b"f\xe9", ""),
		"BINARY partial offsets must apply after transfer decoding without charset conversion",
	);
	exact(
		&mut session,
		"f FETCH 1 (BINARY[1]<0.3>)",
		&literal("BINARY[1]<0>", b"caf", " FLAGS (\\Seen)"),
		"non-PEEK BINARY must set Seen",
	);
}
