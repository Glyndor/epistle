use super::*;

/// `KEYWORD <atom>` (and its negation `UNKEYWORD`) match messages that
/// carry that user keyword; matching is case-insensitive (RFC 9051 §6.4.4).
#[test]
fn search_keyword_and_unkeyword() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
	deliver(dir.path(), b"From: b@x.example\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// Mark only message 1 as `$Junk`.
	let output = session.command_line("a3 STORE 1 +FLAGS ($Junk)");
	assert!(text(&output).contains("a3 OK"), "{}", text(&output));

	// KEYWORD $Junk matches only message 1.
	let response = text(&session.command_line("a4 SEARCH KEYWORD $Junk"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// UNKEYWORD $Junk matches every other message.
	let response = text(&session.command_line("a5 SEARCH UNKEYWORD $Junk"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// Matching is case-insensitive: $junk and $JUNK both match.
	let response = text(&session.command_line("a6 SEARCH KEYWORD $junk"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// A keyword no message carries matches nothing.
	let response = text(&session.command_line("a7 SEARCH KEYWORD $Forwarded"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}
