use super::*;

#[test]
fn searchres_reset_on_select() {
	// RFC 5182 §2.1: a successful SELECT / EXAMINE resets the current
	// search result variable to the empty sequence. A later use of `$`
	// must therefore refuse with NO [SEARCHRES].
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: keeps\r\n\r\none\r\n");
	deliver(dir.path(), b"Subject: keeps\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a1 SELECT INBOX");
	assert!(text(&session.command_line("a2 SEARCH ALL RETURN (SAVE)")).contains("a2 OK"));

	// Re-select the same mailbox; the saved set is gone.
	assert!(text(&session.command_line("a3 SELECT INBOX")).contains("a3 OK"));
	let response = text(&session.command_line("a4 FETCH $ FLAGS"));
	assert!(
		response.contains("[SEARCHRES]"),
		"$ after SELECT must be rejected with NO [SEARCHRES]: {response}"
	);
}

#[test]
fn searchres_reset_on_close_and_unselect() {
	// Per #976: reset also on CLOSE and UNSELECT, both of which leave the
	// selected mailbox without opening another.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: x\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a1 SELECT INBOX");
	session.command_line("a2 SEARCH ALL RETURN (SAVE)");

	session.command_line("a3 CLOSE");
	let response = text(&session.command_line("a4 FETCH $ FLAGS"));
	assert!(
		response.contains("[SEARCHRES]"),
		"$ after CLOSE must be rejected: {response}"
	);

	// Open the mailbox again, save a set, then UNSELECT.
	session.command_line("a5 SELECT INBOX");
	session.command_line("a6 SEARCH ALL RETURN (SAVE)");
	session.command_line("a7 UNSELECT");
	let response = text(&session.command_line("a8 FETCH $ FLAGS"));
	assert!(
		response.contains("[SEARCHRES]"),
		"$ after UNSELECT must be rejected: {response}"
	);
}

#[test]
fn searchres_saved_set_tracks_messages_across_expunges() {
	// RFC 5182 §2.1: when a message in the saved set is EXPUNGEd, it is
	// automatically removed from the list. The remaining saved entries
	// reference the same messages, not the original sequence numbers.
	// The test saves only the middle message by plain SEARCH, then
	// expunges the first message so the saved value (originally seqno 2)
	// would under the seqno-based bug refer to a different message.
	// After the fix the saved set is keyed by UID; non-UID FETCH $ still
	// resolves to the middle message, not to whatever ends up at the
	// saved seqno position now.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: aaa\r\n\r\none\r\n");
	deliver(dir.path(), b"Subject: middle\r\n\r\ntwo\r\n");
	deliver(dir.path(), b"Subject: ccc\r\n\r\nthree\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a1 SELECT INBOX");

	// Save only the middle message by plain SEARCH. The original
	// response line is "* SEARCH 2".
	let response = text(&session.command_line("a2 SEARCH SUBJECT middle RETURN (SAVE)"));
	assert!(response.contains("a2 OK"), "{response}");

	// Expunge the first message: the mailbox now has two messages at
	// seqnos 1 and 2 with UIDs 2 and 3.
	session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)");
	session.command_line("a4 EXPUNGE");
	let response = text(&session.command_line("a5 STATUS INBOX (MESSAGES)"));
	assert!(response.contains("MESSAGES 2"), "{response}");

	// Non-UID FETCH $ must still resolve to the middle message. Under
	// the seqno-based bug the saved value 2 now points at the third
	// message (UID 3). After the fix the saved set is keyed by UID and
	// $ resolves to the live middle message (UID 2) at seqno 1.
	let response = text(&session.command_line("a6 FETCH $ (UID)"));
	assert!(response.contains("* 1 FETCH"), "{response}");
	assert!(response.contains("UID 2"), "{response}");
	assert!(
		!response.contains("UID 3"),
		"$ must remain anchored to the middle message: {response}"
	);

	// STORE $ +FLAGS (\\Flagged) marks the right message. After the fix
	// the third message is unchanged.
	session.command_line(r"a7 STORE $ +FLAGS (\Flagged)");
	let response = text(&session.command_line("a8 FETCH 2 (UID FLAGS)"));
	assert!(response.contains("UID 3"), "{response}");
	assert!(
		!response.contains("\\Flagged"),
		"\\Flagged must not leak to UID 3: {response}"
	);
	let response = text(&session.command_line("a9 FETCH 1 (FLAGS)"));
	assert!(response.contains("\\Flagged"), "{response}");
}
