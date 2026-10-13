//! Two sessions on one mailbox. Each test replays the exchange one of
//! Dovecot's imaptest scripts sends (`close`, `expunge`, `expunge2`,
//! `store`, `move`): what one session changes, the other must learn
//! through EXPUNGE and FETCH responses before its message count moves
//! (RFC 9051 §7.4.1, §7.5.1; RFC 3501 §7.4.1).

use super::*;

/// `messages` delivered to INBOX, then two sessions that both SELECT it.
fn two_sessions(messages: usize) -> (tempfile::TempDir, Session, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	for _ in 0..messages {
		deliver(dir.path(), b"Subject: message\r\n\r\nbody\r\n");
	}
	let mut first = logged_in(dir.path());
	let mut second = logged_in(dir.path());
	assert!(text(&first.command_line("a SELECT INBOX")).contains("a OK"));
	assert!(text(&second.command_line("b SELECT INBOX")).contains("b OK"));
	(dir, first, second)
}

/// imaptest `close`: a CLOSE in one session expunges silently there, and
/// the other session hears each removal as EXPUNGE, never as a lower
/// EXISTS.
#[test]
fn close_in_one_session_is_announced_as_expunges_in_the_other() {
	let (_dir, mut first, mut second) = two_sessions(3);
	first.command_line(r"a STORE 1,3 +FLAGS (\Deleted)");
	assert_eq!(
		text(&first.command_line("a CLOSE")),
		"a OK CLOSE completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b NOOP")),
		"* 3 EXPUNGE\r\n* 1 EXPUNGE\r\nb OK NOOP completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b NOOP")),
		"b OK NOOP completed\r\n"
	);
}

/// imaptest `expunge` part 1: FETCH keeps the old numbering, CHECK
/// announces the expunges and the flag changes, and FETCH afterwards
/// sees the other session's flags.
#[test]
fn check_announces_expunges_and_flag_changes_from_another_session() {
	let (_dir, mut first, mut second) = two_sessions(8);
	first.command_line(r"a STORE 1,3 FLAGS (\Deleted)");
	first.command_line(r"a STORE 2,4 FLAGS (\Seen)");
	assert_eq!(
		text(&first.command_line("a EXPUNGE")),
		"* 1 EXPUNGE\r\n* 2 EXPUNGE\r\na OK EXPUNGE completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b FETCH 2,4 (UID)")),
		"* 2 FETCH (UID 2)\r\n* 4 FETCH (UID 4)\r\nb OK FETCH completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b CHECK")),
		"* 3 EXPUNGE\r\n* 1 EXPUNGE\r\n\
		 * 1 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS (\\Seen))\r\n\
		 b OK CHECK completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b FETCH 1:2 (UID FLAGS)")),
		"* 1 FETCH (UID 2 FLAGS (\\Seen))\r\n* 2 FETCH (UID 4 FLAGS (\\Seen))\r\n\
		 b OK FETCH completed\r\n"
	);
}

/// imaptest `expunge2`: FETCH, STORE and SEARCH must not announce an
/// expunge (RFC 3501 §7.4.1), so their sequence numbers stay the ones the
/// client knows; the next NOOP announces it.
#[test]
fn fetch_store_and_search_hold_back_expunges_until_noop() {
	let (_dir, mut first, mut second) = two_sessions(3);
	first.command_line(r"a STORE 1 +FLAGS (\Deleted)");
	first.command_line("a EXPUNGE");
	assert_eq!(
		text(&second.command_line("b FETCH 2 (UID)")),
		"* 2 FETCH (UID 2)\r\nb OK FETCH completed\r\n"
	);
	assert_eq!(
		text(&second.command_line(r"b STORE 2 FLAGS (\Seen)")),
		"* 2 FETCH (FLAGS (\\Seen))\r\nb OK STORE completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b SEARCH ALL")),
		"* SEARCH 1 2 3\r\nb OK SEARCH completed\r\n"
	);
	assert_eq!(
		text(&second.command_line("b NOOP")),
		"* 1 EXPUNGE\r\nb OK NOOP completed\r\n"
	);
}

/// imaptest `store`: a STORE that adds or removes flags applies to the
/// flags on disk, so two sessions do not undo each other's changes.
#[test]
fn store_from_two_sessions_keeps_both_changes() {
	let (_dir, mut first, mut second) = two_sessions(1);
	first.command_line(r"a STORE 1 FLAGS (\Seen)");
	assert_eq!(
		text(&second.command_line("b CHECK")),
		"* 1 FETCH (FLAGS (\\Seen))\r\nb OK CHECK completed\r\n"
	);
	first.command_line(r"a STORE 1 +FLAGS (\Answered)");
	assert_eq!(
		text(&second.command_line(r"b STORE 1 -FLAGS (\Seen)")),
		"* 1 FETCH (FLAGS (\\Answered))\r\nb OK STORE completed\r\n"
	);
	assert_eq!(
		text(&first.command_line("a CHECK")),
		"* 1 FETCH (FLAGS (\\Answered))\r\na OK CHECK completed\r\n"
	);
	assert_eq!(
		text(&first.command_line("a FETCH 1 FLAGS")),
		"* 1 FETCH (FLAGS (\\Answered))\r\na OK FETCH completed\r\n"
	);
}

/// A keyword another session introduced is announced in FLAGS before the
/// FETCH that carries it (RFC 9051 §7.3.5).
#[test]
fn check_announces_a_new_keyword_before_the_fetch_that_carries_it() {
	let (_dir, mut first, mut second) = two_sessions(2);
	first.command_line("a STORE 2 +FLAGS ($hello)");
	assert_eq!(
		text(&second.command_line("b CHECK")),
		"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft $hello)\r\n\
		 * 2 FETCH (FLAGS ($hello))\r\nb OK CHECK completed\r\n"
	);
}

/// An APPEND to the selected mailbox announces another session's
/// expunges before the new count, instead of renumbering in silence.
#[test]
fn append_announces_expunges_before_the_new_count() {
	let (_dir, mut first, mut second) = two_sessions(2);
	first.command_line(r"a STORE 1 +FLAGS (\Deleted)");
	first.command_line("a EXPUNGE");
	assert!(text(&second.command_line("b APPEND INBOX {6}")).starts_with("+ "));
	let reply = text(&second.literal_done(b"x\r\n\r\nx"));
	assert!(
		reply.starts_with("* 1 EXPUNGE\r\n* 2 EXISTS\r\nb OK [APPENDUID "),
		"{reply}"
	);
}

/// IDLE reports another session's flag change as FETCH (RFC 9051 §6.3.13).
#[test]
fn idle_reports_flag_changes_from_another_session() {
	let (_dir, mut first, mut second) = two_sessions(2);
	assert_eq!(text(&second.command_line("b IDLE")), "+ idling\r\n");
	first.command_line(r"a STORE 2 +FLAGS (\Flagged)");
	assert_eq!(
		second.check_idle().map(|o| text(&o)),
		Some("* 2 FETCH (FLAGS (\\Flagged))\r\n".to_string())
	);
	assert_eq!(second.check_idle().map(|o| text(&o)), None);
}
