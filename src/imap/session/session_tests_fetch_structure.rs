use super::fetch_envelope::{PLAIN, SIMPLE, exact, selected};

pub(super) const ALTERNATIVE: &[u8] = b"Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nplain\r\n--a\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n--a--\r\n";
pub(super) const MIXED: &[u8] = b"Content-Type: multipart/mixed; boundary=m\r\nContent-Disposition: inline\r\nContent-Language: en, es\r\nContent-Location: /mail\r\n\r\n--m\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ntext\r\n--m\r\nContent-Type: application/octet-stream; name=hello.bin\r\nContent-Disposition: attachment; filename=hello.bin\r\nContent-ID: <file@example.org>\r\nContent-Description: data\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--m--\r\n";
pub(super) fn nested() -> Vec<u8> {
	let mut raw = b"Content-Type: multipart/mixed; boundary=n\r\n\r\n--n\r\nContent-Type: message/rfc822\r\n\r\n".to_vec();
	raw.extend_from_slice(PLAIN);
	raw.extend_from_slice(b"\r\n--n--\r\n");
	raw
}

pub(super) const TEXT: &str =
	"(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 7 1)";
pub(super) const TEXT_EXT: &str =
	"(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 7 1 NIL NIL NIL NIL)";

#[test]
fn fetch_structure_plain_body_and_uid() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (BODYSTRUCTURE BODY)",
		format!("* 1 FETCH (BODYSTRUCTURE {TEXT_EXT} BODY {TEXT})\r\nf OK FETCH completed\r\n")
			.as_bytes(),
		"BODYSTRUCTURE and BODY must describe plain text with exact octets and lines",
	);
	exact(
		&mut session,
		"u UID FETCH 1:* (BODYSTRUCTURE) (CHANGEDSINCE 0)",
		format!(
			"* 1 FETCH (BODYSTRUCTURE {TEXT_EXT} UID 1 MODSEQ (1))\r\nu OK FETCH completed\r\n"
		)
		.as_bytes(),
		"UID BODYSTRUCTURE must preserve CHANGEDSINCE",
	);
}

#[test]
fn fetch_structure_alternative() {
	let (_dir, mut session) = selected(ALTERNATIVE);
	let body = "((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 5 0)(\"TEXT\" \"HTML\" NIL NIL NIL \"7BIT\" 8 0) \"ALTERNATIVE\")";
	let ext = "((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 5 0 NIL NIL NIL NIL)(\"TEXT\" \"HTML\" NIL NIL NIL \"7BIT\" 8 0 NIL NIL NIL NIL) \"ALTERNATIVE\" (\"BOUNDARY\" \"a\") NIL NIL NIL)";
	exact(
		&mut session,
		"f FETCH 1 (BODY BODYSTRUCTURE)",
		format!("* 1 FETCH (BODY {body} BODYSTRUCTURE {ext})\r\nf OK FETCH completed\r\n")
			.as_bytes(),
		"BODY must omit extensions throughout the alternative tree",
	);
}

#[test]
fn fetch_structure_mixed_attachment_extensions() {
	let (_dir, mut session) = selected(MIXED);
	let ext = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"utf-8\") NIL NIL \"7BIT\" 4 0 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"hello.bin\") \"<file@example.org>\" \"data\" \"BASE64\" 8 NIL (\"ATTACHMENT\" (\"FILENAME\" \"hello.bin\")) NIL NIL) \"MIXED\" (\"BOUNDARY\" \"m\") (\"INLINE\" NIL) (\"en\" \"es\") \"/mail\")";
	exact(
		&mut session,
		"f FETCH 1 (BODYSTRUCTURE)",
		format!("* 1 FETCH (BODYSTRUCTURE {ext})\r\nf OK FETCH completed\r\n").as_bytes(),
		"BODYSTRUCTURE must describe encoded attachment octets and MIME extensions",
	);

	let body = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"utf-8\") NIL NIL \"7BIT\" 4 0)(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"hello.bin\") \"<file@example.org>\" \"data\" \"BASE64\" 8) \"MIXED\")";
	exact(
		&mut session,
		"f FETCH 1 (BODY)",
		format!("* 1 FETCH (BODY {body})\r\nf OK FETCH completed\r\n").as_bytes(),
		"BODY must omit single-part and multipart attachment extensions",
	);
}

#[test]
fn fetch_structure_nested_message() {
	let (_dir, mut session) = selected(&nested());
	let body = format!(
		"((\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" {} {SIMPLE} {TEXT} 7) \"MIXED\")",
		PLAIN.len()
	);
	exact(
		&mut session,
		"f FETCH 1 (BODY)",
		format!("* 1 FETCH (BODY {body})\r\nf OK FETCH completed\r\n").as_bytes(),
		"BODY must include the encapsulated envelope, structure and line count",
	);

	let structure = format!(
		"((\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" {} {SIMPLE} {TEXT_EXT} 7 NIL NIL NIL NIL) \"MIXED\" (\"BOUNDARY\" \"n\") NIL NIL NIL)",
		PLAIN.len()
	);
	exact(
		&mut session,
		"f FETCH 1 (BODYSTRUCTURE)",
		format!("* 1 FETCH (BODYSTRUCTURE {structure})\r\nf OK FETCH completed\r\n").as_bytes(),
		"BODYSTRUCTURE must include extensions inside encapsulated messages",
	);
}
