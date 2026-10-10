use super::*;

#[test]
fn failed_select_after_selected_carries_closed_and_deselects() {
	// RFC 9051 §6.3.2: a SELECT that fails after another mailbox is selected
	// moves the session back to the authenticated state and announces the
	// implicit close with [CLOSED]. A subsequent STORE that needs a selected
	// mailbox is refused, and the original mailbox on disk is unchanged.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: rfc9051-1\r\n\r\noriginal\r\n");
	let mut session = logged_in(dir.path());
	assert!(
		text(&session.command_line("a1 SELECT INBOX")).contains("a1 OK"),
		"setup SELECT must succeed"
	);

	let response = text(&session.command_line("a2 SELECT DoesNotExist"));
	assert_eq!(
		response, "a2 NO [CLOSED] no such mailbox\r\n",
		"failed SELECT after SELECT INBOX must announce the implicit close"
	);

	// A command that requires a selected mailbox now sees none.
	let response = text(&session.command_line("a3 STORE 1 +FLAGS (\\Seen)"));
	assert_eq!(
		response, "a3 BAD no mailbox selected\r\n",
		"STORE after failed SELECT must refuse without touching INBOX"
	);

	// The original mailbox is intact: selecting it again and fetching flags
	// shows no \\Seen was applied.
	assert!(text(&session.command_line("a4 SELECT INBOX")).contains("a4 OK"));
	let response = text(&session.command_line("a5 FETCH 1 (FLAGS)"));
	assert!(
		!response.contains("\\Seen"),
		"original INBOX must still be clean: {response}"
	);
}

#[test]
fn failed_select_when_nothing_was_selected_lacks_closed() {
	// [CLOSED] is the boundary between the closed and the newly-opened
	// mailbox; there is no closed mailbox here, so the response omits it.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a1 SELECT StillMissing"));
	assert_eq!(
		response, "a1 NO no such mailbox\r\n",
		"first failing SELECT must not carry [CLOSED] when nothing was selected"
	);

	// A subsequent STORE still has nothing to land on.
	let response = text(&session.command_line("a2 STORE 1 +FLAGS (\\Seen)"));
	assert_eq!(response, "a2 BAD no mailbox selected\r\n");
}

#[test]
fn failed_examine_deselects_with_closed_just_like_select() {
	// §6.3.3: EXAMINE shares the SELECT deselect discipline.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: rfc9051-examine\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	assert!(text(&session.command_line("a1 SELECT INBOX")).contains("a1 OK"));
	let response = text(&session.command_line("a2 EXAMINE Nope"));
	assert_eq!(response, "a2 NO [CLOSED] no such mailbox\r\n");
	let response = text(&session.command_line("a3 EXPUNGE"));
	assert_eq!(response, "a3 BAD no mailbox selected\r\n");
}
