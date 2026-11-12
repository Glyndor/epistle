//! MULTISEARCH scopes and SEARCHRES result saving.

use super::search_criteria::deliver_to;
use super::*;

#[test]
fn multisearch_across_explicit_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	deliver(dir.path(), b"Subject: b\r\n\r\ntwo\r\n");
	deliver_to(dir.path(), "Archive", b"Subject: c\r\n\r\nthree\r\n");
	let mut session = logged_in(dir.path());

	// MULTISEARCH does not require a selected mailbox; it names them.
	let response = text(
		&session
			.command_line("m1 ESEARCH IN (mailboxes (\"INBOX\" \"Archive\")) RETURN (COUNT) ALL"),
	);
	assert!(
		response.contains("MAILBOX \"INBOX\" UIDVALIDITY"),
		"{response}"
	);
	assert!(
		response.contains("MAILBOX \"Archive\" UIDVALIDITY"),
		"{response}"
	);
	// INBOX has two, Archive has one.
	assert!(response.contains("UID COUNT 2"), "{response}");
	assert!(response.contains("UID COUNT 1"), "{response}");
	assert!(response.contains("m1 OK SEARCH completed"), "{response}");
}

#[test]
fn multisearch_defaults_to_selected_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	deliver(dir.path(), b"Subject: b\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("m1 SELECT INBOX");

	// No IN clause → the selected mailbox; default RETURN is ALL (UIDs).
	let response = text(&session.command_line("m2 ESEARCH ALL"));
	assert!(
		response.contains("MAILBOX \"INBOX\" UIDVALIDITY"),
		"{response}"
	);
	assert!(response.contains("UID ALL 1:2"), "{response}");
}

#[test]
fn multisearch_selected_without_selection_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	// Authenticated but no mailbox selected.
	let response = text(&session.command_line("m1 ESEARCH ALL"));
	assert!(response.contains("m1 BAD"), "{response}");
}

#[test]
fn multisearch_subtree_matches_root_not_same_prefix_sibling() {
	// A subtree is its root and the folders under it. A sibling that merely
	// shares the name as a prefix ("Workshop") must not be included.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver_to(dir.path(), "Work", b"Subject: a\r\n\r\none\r\n");
	deliver_to(dir.path(), "Workshop", b"Subject: b\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());

	let response =
		text(&session.command_line("m1 ESEARCH IN (subtree (\"Work\")) RETURN (COUNT) ALL"));
	assert!(
		response.contains("MAILBOX \"Work\" UIDVALIDITY"),
		"{response}"
	);
	assert!(
		!response.contains("MAILBOX \"Workshop\""),
		"sibling leaked: {response}"
	);
}

#[test]
fn multisearch_personal_scope_searches_all_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: a\r\n\r\none\r\n");
	deliver_to(dir.path(), "Archive", b"Subject: b\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());

	let response = text(&session.command_line("m1 ESEARCH IN (personal) RETURN (COUNT) ALL"));
	assert!(
		response.contains("MAILBOX \"INBOX\" UIDVALIDITY"),
		"{response}"
	);
	assert!(
		response.contains("MAILBOX \"Archive\" UIDVALIDITY"),
		"{response}"
	);
}

#[test]
fn searchres_save_and_dollar_shortcut() {
	// SEARCHRES (RFC 5182): `SEARCH RETURN (SAVE)` stores the result set so
	// the client can reference it via `$` in subsequent FETCH/STORE/COPY.
	// Plain SEARCH saves sequence numbers; UID SEARCH saves UIDs.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
	deliver(
		dir.path(),
		b"From: b@x.example\r\nSubject: hi\r\n\r\ntwo\r\n",
	);
	deliver(
		dir.path(),
		b"From: c@x.example\r\nSubject: hi\r\n\r\nthree\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// Save every message that has a "hi" subject (sequences 2 and 3).
	let response = text(&session.command_line("a3 SEARCH SUBJECT hi RETURN (SAVE)"));
	assert!(response.contains("a3 OK SEARCH completed"), "{response}");

	// FETCH $ uses the saved set: messages 2 and 3, never 1.
	let response = text(&session.command_line("a4 FETCH $ FLAGS"));
	assert!(response.contains("* 2 FETCH"), "{response}");
	assert!(response.contains("* 3 FETCH"), "{response}");
	assert!(!response.contains("* 1 FETCH"), "{response}");

	// STORE $ applies to the saved set (mark them \Seen).
	let response = text(&session.command_line(r"a5 STORE $ +FLAGS (\Seen)"));
	assert!(
		response.contains(r"* 2 FETCH (FLAGS (\Seen))"),
		"{response}"
	);
	assert!(
		response.contains(r"* 3 FETCH (FLAGS (\Seen))"),
		"{response}"
	);
	assert!(response.contains("a5 OK STORE completed"), "{response}");

	// UID SEARCH saves UIDs; UID FETCH $ uses them.
	let response = text(&session.command_line("a6 UID SEARCH SUBJECT hi RETURN (SAVE)"));
	assert!(response.contains("a6 OK"), "{response}");
	let response = text(&session.command_line("a7 UID FETCH $ UID"));
	assert!(response.contains("* 2 FETCH"), "{response}");
	assert!(response.contains("* 3 FETCH"), "{response}");
	assert!(response.contains("UID 2"), "{response}");
	assert!(response.contains("UID 3"), "{response}");

	// Type mismatch: $ from a UID SEARCH is not valid in a non-UID command.
	let response = text(&session.command_line("a8 FETCH $ FLAGS"));
	assert!(
		response.contains("a8 NO"),
		"$ from UID SEARCH must be rejected for non-UID FETCH: {response}"
	);

	// Re-SAVE replaces the reservation.
	let response = text(&session.command_line("a9 SEARCH ALL RETURN (SAVE)"));
	assert!(response.contains("a9 OK"), "{response}");
	let response = text(&session.command_line("a10 FETCH $ FLAGS"));
	assert!(response.contains("* 1 FETCH"), "{response}");
	assert!(response.contains("* 2 FETCH"), "{response}");
	assert!(response.contains("* 3 FETCH"), "{response}");

	// Capability advertises SEARCHRES.
	assert!(
		text(&session.command_line("a11 CAPABILITY")).contains("SEARCHRES"),
		"capability should advertise SEARCHRES"
	);

	// SAVE combined with other return options: still stores the set and
	// emits the requested fields alongside.
	let response = text(&session.command_line("a12 SEARCH RETURN (SAVE COUNT) ALL"));
	assert!(response.contains("COUNT 3"), "{response}");
}

#[test]
fn searchres_dollar_without_save_is_rejected() {
	// Per RFC 5182 §5.1, using $ when no SAVE has been issued is a protocol
	// error. The server answers NO so the client knows to re-issue SEARCH.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let response = text(&session.command_line("a3 FETCH $ FLAGS"));
	assert!(response.contains("a3 NO"), "{response}");
}
