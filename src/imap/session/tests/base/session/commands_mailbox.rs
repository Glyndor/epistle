//! IMAP session mailbox management, COPY and REPLACE command tests.

use super::*;

#[test]
fn mailbox_lifecycle() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let output = session.command_line("a2 CREATE Work");
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	// APPEND into the new mailbox works now.
	let output = session.command_line("a3 APPEND Work {10}");
	assert_eq!(output.collect_literal, Some(10));
	let output = session.literal_done(b"sent body\n");
	assert!(text(&output).contains("a3 OK"), "{}", text(&output));

	let output = session.command_line("a4 SELECT Work");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	session.command_line("a5 CLOSE");

	let output = session.command_line(r#"a6 LIST "" "*""#);
	let response = text(&output);
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("\"Work\""), "{response}");

	let output = session.command_line("a7 RENAME Work Outbox");
	assert!(text(&output).contains("a7 OK"), "{}", text(&output));
	let output = session.command_line("a8 SELECT Outbox");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	session.command_line("a9 CLOSE");

	let output = session.command_line("b1 DELETE Outbox");
	assert!(text(&output).contains("b1 OK"), "{}", text(&output));
	let output = session.command_line("b2 SELECT Outbox");
	assert!(text(&output).contains("b2 NO"), "{}", text(&output));
}

#[test]
fn mailbox_management_guards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// INBOX cannot be created, deleted or renamed.
	assert!(text(&session.command_line("a2 CREATE INBOX")).contains("a2 NO"));
	assert!(text(&session.command_line("a3 DELETE INBOX")).contains("a3 NO"));
	assert!(text(&session.command_line("a4 RENAME INBOX X")).contains("a4 NO"));
	// Traversal and invalid names are refused.
	assert!(text(&session.command_line("a5 CREATE ../escape")).contains("a5 NO"));
	assert!(text(&session.command_line("a6 DELETE missing")).contains("a6 NO"));
	// Duplicate create fails.
	session.command_line("a7 CREATE Drafts");
	assert!(text(&session.command_line("a8 CREATE Drafts")).contains("a8 NO"));
}

#[test]
fn copy_preserves_source_and_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Archive");
	session.command_line("a3 SELECT INBOX");
	session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");

	let output = session.command_line("a5 COPY 1 Archive");
	let response = text(&output);
	assert!(response.contains("a5 OK"), "{response}");
	// UIDPLUS COPYUID: source and destination UID sets reported.
	assert!(response.contains("[COPYUID "), "{response}");
	assert!(response.contains("COPY completed"), "{response}");

	// Source intact.
	let output = session.command_line("a6 FETCH 1 (FLAGS)");
	assert!(text(&output).contains(r"FLAGS (\Seen)"));
	session.command_line("a7 CLOSE");

	// Target has the copy with flags.
	let output = session.command_line("a8 SELECT Archive");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	let output = session.command_line("a9 FETCH 1 (FLAGS BODY[])");
	let response = text(&output);
	assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
	assert!(response.contains("one"), "{response}");
}

#[test]
fn replace_appends_new_and_expunges_source() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nfirst\r\n");
	deliver(dir.path(), b"Subject: two\r\n\r\nsecond\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let output = session.command_line("a3 REPLACE 1 INBOX {23}");
	assert_eq!(output.collect_literal, Some(23));
	let output = session.literal_done(b"Subject: new\r\n\r\nfresh\r\n");
	let response = text(&output);
	assert!(response.contains("* 1 EXPUNGE"), "{response}");
	assert!(response.contains("[APPENDUID "), "{response}");
	assert!(response.contains("REPLACE completed"), "{response}");

	// Two messages remain (one expunged, one appended): old "two" and "new".
	let output = session.command_line("a4 SELECT INBOX");
	assert!(text(&output).contains("* 2 EXISTS"), "{}", text(&output));
	let output = session.command_line("a5 FETCH 1:2 (BODY[])");
	let response = text(&output);
	assert!(response.contains("Subject: two"), "{response}");
	assert!(response.contains("Subject: new"), "{response}");
	assert!(!response.contains("Subject: one"), "{response}");
}

#[test]
fn replace_rejects_unknown_source_and_no_selection() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nx\r\n");
	let mut session = logged_in(dir.path());

	// No mailbox selected yet.
	let output = session.command_line("a2 REPLACE 1 INBOX {5}");
	assert!(text(&output).contains("a2 NO"), "{}", text(&output));
	assert_eq!(output.collect_literal, None);

	session.command_line("a3 SELECT INBOX");
	let output = session.command_line("a4 REPLACE 9 INBOX {5}");
	assert!(
		text(&output).contains("no such message"),
		"{}",
		text(&output)
	);
	assert_eq!(output.collect_literal, None);
}

/// REPLACE (RFC 8508) must resolve the target to a UID at command
/// start: a concurrent expunge that reorders the snapshot between
/// `REPLACE` and its literal would otherwise let the trailing
/// `remove_at(seq)` silently delete a different message. The test
/// simulates the race by appending a new message and expunging the
/// original target between `REPLACE 1` and `literal_done`, then
/// asserts the survivor (m2) is still on disk.
#[test]
fn replace_with_concurrent_expunge_keeps_its_target() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nfirst\r\n");
	deliver(dir.path(), b"Subject: two\r\n\r\nsecond\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// REPLACE message 1 (uid=1, "one"). The session resolves
	// `sequence=1` to a UID but does not start the literal read
	// until the test returns to the event loop.
	let output = session.command_line("a3 REPLACE 1 INBOX {23}");
	assert_eq!(output.collect_literal, Some(23));

	// Simulate a concurrent session expunging the target. We do
	// this on disk (deliver a new message then ask the IMAP
	// session to expunge it) so the next snapshot the server reads
	// reorders the surviving messages.
	deliver(dir.path(), b"Subject: three\r\n\r\nthird\r\n");
	session.command_line("a4 STORE 1 +FLAGS (\\Deleted)");
	session.command_line("a5 EXPUNGE");
	// The mailbox now has: two (uid=2), three (uid=3) at seq=1,2.
	// With the bug, REPLACE 1's stored seq=1 would now mean
	// "two" and delete it.

	let output = session.literal_done(b"Subject: new\r\n\r\nfresh\r\n");
	let response = text(&output);
	assert!(
		response.contains("REPLACE completed"),
		"REPLACE should still complete when the target is already gone: {response}"
	);

	// The survivor ("two") must still be on disk; the new
	// message ("new") is the replacement; "three" survives. The
	// file system check is the real assertion: "two" is the message
	// REPLACE would have wrongly deleted.
	let inbox = dir.path().join("accounts/alice/new");
	let subjects: Vec<String> = std::fs::read_dir(&inbox)
		.unwrap()
		.filter_map(|e| e.ok())
		.filter_map(|e| std::fs::read_to_string(e.path()).ok())
		.map(|body| {
			body.lines()
				.find(|l| l.starts_with("Subject: "))
				.unwrap_or("")
				.to_string()
		})
		.collect();
	assert!(
		subjects.iter().any(|s| s == "Subject: two"),
		"survivor Subject: two must NOT have been deleted; saw: {subjects:?}"
	);
	assert!(
		subjects.iter().any(|s| s == "Subject: new"),
		"the new replacement must be present; saw: {subjects:?}"
	);
	assert!(
		!subjects.iter().any(|s| s == "Subject: one"),
		"the original target Subject: one was already expunged: {subjects:?}"
	);
}

#[test]
fn replace_refused_on_read_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nx\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 EXAMINE INBOX");
	let output = session.command_line("a3 REPLACE 1 INBOX {5}");
	assert!(text(&output).contains("read-only"), "{}", text(&output));
	assert_eq!(output.collect_literal, None);
}

#[test]
fn fetch_preview_returns_collapsed_snippet() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Subject: hi\r\n\r\nThis is   the\r\nbody text.\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line("a3 FETCH 1 (PREVIEW)");
	let response = text(&output);
	assert!(
		response.contains("PREVIEW \"This is the body text.\""),
		"{response}"
	);
}
