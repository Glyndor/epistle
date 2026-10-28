use super::*;

#[test]
fn setmetadata_then_getmetadata_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let response = text(&session.command_line("a2 SETMETADATA INBOX (/private/comment \"hello\")"));
	assert!(
		response.contains("a2 OK SETMETADATA completed"),
		"{response}"
	);

	let response = text(&session.command_line("a3 GETMETADATA INBOX /private/comment"));
	assert!(response.contains("* METADATA \"INBOX\""), "{response}");
	assert!(response.contains("/private/comment"), "{response}");
	assert!(response.contains("hello"), "{response}");
	assert!(
		response.contains("a3 OK GETMETADATA completed"),
		"{response}"
	);
}

#[test]
fn setmetadata_nil_deletes_entry() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SETMETADATA INBOX (/private/x \"v\")");
	session.command_line("a3 SETMETADATA INBOX (/private/x NIL)");
	// Deleted entry yields no untagged METADATA line.
	let response = text(&session.command_line("a4 GETMETADATA INBOX /private/x"));
	assert!(!response.contains("* METADATA"), "{response}");
	assert!(
		response.contains("a4 OK GETMETADATA completed"),
		"{response}"
	);
}

#[test]
fn server_level_metadata_uses_empty_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SETMETADATA \"\" (/shared/vendor/x \"y\")");
	let response = text(&session.command_line("a3 GETMETADATA \"\" /shared/vendor/x"));
	assert!(response.contains("/shared/vendor/x"), "{response}");
	assert!(response.contains("y"), "{response}");
}

#[test]
fn setmetadata_rejects_bad_entry_and_missing_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 SETMETADATA INBOX (badentry \"v\")"));
	assert!(response.contains("a2 BAD"), "{response}");
	let response = text(&session.command_line("a3 GETMETADATA Nope /private/x"));
	assert!(response.contains("a3 NO no such mailbox"), "{response}");
}

#[test]
fn uidonly_rejects_sequence_commands() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 ENABLE UIDONLY");
	session.command_line("a3 SELECT INBOX");

	// A sequence-number FETCH is refused; UID FETCH works.
	let response = text(&session.command_line("a4 FETCH 1 (FLAGS)"));
	assert!(response.contains("a4 BAD [UIDREQUIRED]"), "{response}");

	let response = text(&session.command_line("a5 UID FETCH 1 (FLAGS)"));
	assert!(response.contains("* UIDFETCH 1 ("), "{response}");
	assert!(!response.contains("FETCH (UID"), "no seq FETCH: {response}");
}

#[test]
fn uidonly_enable_refused_when_selected() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 ENABLE UIDONLY"));
	assert!(response.contains("a3 BAD"), "{response}");
}

#[test]
fn uidonly_expunge_reports_vanished() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	deliver(dir.path(), b"Subject: b\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 ENABLE UIDONLY");
	session.command_line("a3 SELECT INBOX");
	session.command_line("a4 UID STORE 1 +FLAGS (\\Deleted)");
	let response = text(&session.command_line("a5 EXPUNGE"));
	assert!(response.contains("* VANISHED 1"), "{response}");
	assert!(
		!response.contains("EXPUNGE\r\n* "),
		"no seq EXPUNGE: {response}"
	);
}
