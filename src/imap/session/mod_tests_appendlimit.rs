//! APPENDLIMIT (RFC 7889): the advertised number is the size APPEND
//! accepts, and one octet more is refused with TOOBIG.

use super::*;
use crate::imap::command::DEFAULT_APPEND_LIMIT;

const APPEND_LIMIT: usize = DEFAULT_APPEND_LIMIT;

#[test]
fn capability_and_status_carry_the_same_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let capability = text(&session.command_line("c CAPABILITY"));
	assert!(
		capability.contains(&format!(" APPENDLIMIT={APPEND_LIMIT} ")),
		"{capability}"
	);
	let status = text(&session.command_line("s STATUS INBOX (APPENDLIMIT MESSAGES)"));
	assert!(
		status.starts_with(&format!(
			"* STATUS \"INBOX\" (APPENDLIMIT {APPEND_LIMIT} MESSAGES 0)\r\n"
		)),
		"{status}"
	);
	let listed = text(&session.command_line("l LIST \"\" \"INBOX\" RETURN (STATUS (APPENDLIMIT))"));
	assert!(
		listed.contains(&format!("(APPENDLIMIT {APPEND_LIMIT})")),
		"{listed}"
	);
}

#[test]
fn a_message_of_exactly_the_limit_is_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let ready = text(&session.command_line(&format!("p APPEND INBOX {{{APPEND_LIMIT}}}")));
	assert!(ready.starts_with("+ "), "{ready}");
	let mut message = b"Subject: big\r\n\r\n".to_vec();
	message.resize(APPEND_LIMIT, b'x');
	let done = text(&session.literal_done(&message));
	assert!(done.contains("p OK"), "{done}");
}

#[test]
fn one_octet_more_is_refused_with_toobig() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let over = APPEND_LIMIT + 1;
	// Synchronizing: refused before the client sends anything.
	let output = session.command_line(&format!("p APPEND INBOX {{{over}}}"));
	assert_eq!(
		text(&output),
		"p NO [TOOBIG] message exceeds APPENDLIMIT\r\n"
	);
	assert_eq!(output.collect_literal, None);
	assert_eq!(output.discard_literal, None);
	// Non-synchronizing: the payload is already sent and is discarded.
	let output = session.command_line(&format!("q APPEND INBOX (\\Seen) {{{over}+}}"));
	assert_eq!(
		text(&output),
		"q NO [TOOBIG] message exceeds APPENDLIMIT\r\n"
	);
	assert_eq!(output.discard_literal, Some(over));
	// REPLACE carries a message too, under the same limit.
	session.command_line("a SELECT INBOX");
	let replace = text(&session.command_line(&format!("r REPLACE 1 INBOX {{{over}}}")));
	assert_eq!(replace, "r NO [TOOBIG] message exceeds APPENDLIMIT\r\n");
}

#[test]
fn the_per_session_append_limit_follows_with_append_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path()).with_append_limit(1_048_576);
	let capability = text(&session.command_line("c CAPABILITY"));
	assert!(
		capability.contains(" APPENDLIMIT=1048576 "),
		"the configured cap is the one CAPABILITY advertises: {capability}"
	);
	// 1 MiB + 1 must be refused.
	let over = 1_048_577;
	let output = session.command_line(&format!("p APPEND INBOX {{{over}}}"));
	assert_eq!(
		text(&output),
		"p NO [TOOBIG] message exceeds APPENDLIMIT\r\n"
	);
}

#[test]
fn a_rejected_non_synchronizing_append_discards_its_payload() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// An unclosed flag list: BAD, and the 5 octets already sent go.
	let output = session.command_line("p APPEND INBOX (\\Seen {5+}");
	assert_eq!(text(&output), "p BAD invalid arguments\r\n");
	assert_eq!(output.discard_literal, Some(5));
	let output = session.command_line("p UID REPLACE x INBOX {7+}");
	assert!(text(&output).starts_with("p BAD"), "{}", text(&output));
	assert_eq!(output.discard_literal, Some(7));
}
