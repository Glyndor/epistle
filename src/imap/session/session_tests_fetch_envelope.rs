use super::{deliver, logged_in};

pub(super) const PLAIN: &[u8] = b"Date: Fri, 9 Oct 2026 12:00:00 +0000\r\nSubject: hello\r\nFrom: Alice <alice@example.org>\r\nTo: bob@example.net\r\nMessage-ID: <one@example.org>\r\n\r\nhello\r\n";
pub(super) const SIMPLE: &str = "(\"Fri, 9 Oct 2026 12:00:00 +0000\" \"hello\" ((\"Alice\" NIL \"alice\" \"example.org\")) ((\"Alice\" NIL \"alice\" \"example.org\")) ((\"Alice\" NIL \"alice\" \"example.org\")) ((NIL NIL \"bob\" \"example.net\")) NIL NIL NIL \"<one@example.org>\")";

pub(super) fn selected(raw: &[u8]) -> (tempfile::TempDir, super::Session) {
	let dir = tempfile::tempdir_in(".").unwrap();
	deliver(dir.path(), raw);
	let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(86400);
	for entry in std::fs::read_dir(dir.path().join("accounts/alice/new")).unwrap() {
		std::fs::File::open(entry.unwrap().path())
			.unwrap()
			.set_times(std::fs::FileTimes::new().set_modified(when))
			.unwrap();
	}
	let mut session = logged_in(dir.path());
	session.command_line("s SELECT INBOX");
	(dir, session)
}

pub(super) fn exact(session: &mut super::Session, command: &str, expected: &[u8], message: &str) {
	let actual = session.command_line(command);
	assert!(actual.bytes == expected, "{message}");
}

#[test]
fn fetch_envelope_plain_and_uid_changed_since() {
	let (_dir, mut session) = selected(PLAIN);
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		format!("* 1 FETCH (ENVELOPE {SIMPLE})\r\nf OK FETCH completed\r\n").as_bytes(),
		"ENVELOPE must return the exact plain message envelope",
	);
	exact(
		&mut session,
		"u UID FETCH 1:* (ENVELOPE) (CHANGEDSINCE 0)",
		format!("* 1 FETCH (ENVELOPE {SIMPLE} UID 1 MODSEQ (1))\r\nu OK FETCH completed\r\n")
			.as_bytes(),
		"UID ENVELOPE must preserve CHANGEDSINCE and report identifiers",
	);
}

#[test]
fn fetch_envelope_encoded_names_and_group() {
	let raw = b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\nFrom: =?UTF-8?Q?Alice_Smith?= <alice@example.org>\r\nSender: Sender <s@example.net>\r\nReply-To: reply@example.net\r\nTo: Friends: Bob <bob@example.net>, carol@example.net;\r\nCc: c@example.org\r\nBcc: b@example.org\r\nIn-Reply-To: <prior@example.org>\r\nMessage-ID: <two@example.org>\r\n\r\nx";
	let (_dir, mut session) = selected(raw);
	let expected = "* 1 FETCH (ENVELOPE (NIL \"=?UTF-8?Q?caf=C3=A9?=\" ((\"=?UTF-8?Q?Alice_Smith?=\" NIL \"alice\" \"example.org\")) ((\"Sender\" NIL \"s\" \"example.net\")) ((NIL NIL \"reply\" \"example.net\")) ((NIL NIL \"Friends\" NIL)(\"Bob\" NIL \"bob\" \"example.net\")(NIL NIL \"carol\" \"example.net\")(NIL NIL NIL NIL)) ((NIL NIL \"c\" \"example.org\")) ((NIL NIL \"b\" \"example.org\")) \"<prior@example.org>\" \"<two@example.org>\"))\r\nf OK FETCH completed\r\n";
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		expected.as_bytes(),
		"ENVELOPE must preserve encoded words and group address markers",
	);
}

#[test]
fn fetch_envelope_literals_and_absent_fields() {
	let (_dir, mut session) = selected(b"Subject: a \"quote\"\r\n\tand fold\r\n\r\nx");
	exact(&mut session, "f FETCH 1 (ENVELOPE)", b"* 1 FETCH (ENVELOPE (NIL {20}\r\na \"quote\"\r\n\tand fold NIL NIL NIL NIL NIL NIL NIL NIL))\r\nf OK FETCH completed\r\n", "ENVELOPE must use a literal for a folded quoted subject and NIL for absent fields");
}

#[test]
fn fetch_envelope_source_route_and_literal_octets() {
	let raw =
		b"From: <@relay.example,@gateway.example:alice@example.org>\r\nSubject: caf\xe9\r\n\r\nx";
	let (_dir, mut session) = selected(raw);
	let addr = "((NIL \"@relay.example,@gateway.example\" \"alice\" \"example.org\"))";
	let mut expected = b"* 1 FETCH (ENVELOPE (NIL {4}\r\ncaf\xe9 ".to_vec();
	expected.extend_from_slice(
		format!("{addr} {addr} {addr} NIL NIL NIL NIL NIL))\r\nf OK FETCH completed\r\n")
			.as_bytes(),
	);
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		&expected,
		"ENVELOPE must preserve source routes and non-UTF8 header octets",
	);
}
