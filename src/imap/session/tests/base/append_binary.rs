//! APPEND with a literal8 (RFC 3516 §4.4): binary parts are stored base64
//! encoded, so BODY[] never carries a NUL and BINARY[] gives the octets back.

use super::*;

const MESSAGE: &[u8] = b"From: user@domain.org\r\n\
Mime-Version: 1.0\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: binary\r\n\
\r\n\
\0-\xe4\n\r\n\n";

fn appended(message: &[u8]) -> (tempfile::TempDir, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line(&format!("a1 APPEND INBOX ~{{{}}}", message.len()));
	assert!(text(&output).starts_with("+ "), "{}", text(&output));
	let response = text(&session.literal_done(message));
	assert!(response.contains("a1 OK"), "{response}");
	session.command_line("s SELECT INBOX");
	(dir, session)
}

#[test]
fn binary_part_is_stored_base64() {
	let (_dir, mut session) = appended(MESSAGE);
	let body = session.command_line("f1 FETCH 1 (BODY.PEEK[1])").bytes;
	assert!(!body.contains(&0), "{}", String::from_utf8_lossy(&body));
	assert!(
		String::from_utf8_lossy(&body).contains("BODY[1] {12}\r\nAC3kCg0KCg=="),
		"{}",
		String::from_utf8_lossy(&body)
	);
	let header = text(&session.command_line("f2 FETCH 1 (BODY.PEEK[1.MIME])"));
	assert!(
		header.contains("Content-Transfer-Encoding: base64\r\n"),
		"{header}"
	);
	let mut expected =
		b"* 1 FETCH (BINARY.SIZE[1] 7 BINARY[1] ~{7}\r\n\0-\xe4\n\r\n\n)\r\n".to_vec();
	expected.extend_from_slice(b"f3 OK FETCH completed\r\n");
	assert_eq!(
		session
			.command_line("f3 FETCH 1 (BINARY.SIZE[1] BINARY.PEEK[1])")
			.bytes,
		expected
	);
}

#[test]
fn a_plain_literal_is_stored_as_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let message = b"Content-Transfer-Encoding: binary\r\n\r\nab\r\n";
	session.command_line(&format!("a1 APPEND INBOX {{{}}}", message.len()));
	assert!(text(&session.literal_done(message)).contains("a1 OK"));
	session.command_line("s SELECT INBOX");
	let body = text(&session.command_line("f FETCH 1 (BODY.PEEK[])"));
	assert!(body.contains("binary\r\n\r\nab\r\n"), "{body}");
}
