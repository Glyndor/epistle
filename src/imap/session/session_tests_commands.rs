use super::*;

#[test]
fn uid_fetch_changedsince_vanished_reports_expunged() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 SELECT INBOX"));
	let modseq: u64 = {
		let after = response.split("[HIGHESTMODSEQ ").nth(1).expect("modseq");
		after.split(']').next().unwrap().trim().parse().unwrap()
	};
	session.command_line("a3 STORE 1 +FLAGS (\\Deleted)");
	session.command_line("a4 EXPUNGE");

	// UID FETCH with CHANGEDSINCE ... VANISHED reports the expunged UID.
	let cmd = format!("a5 UID FETCH 1:* (FLAGS) (CHANGEDSINCE {modseq} VANISHED)");
	let response = text(&session.command_line(&cmd));
	assert!(response.contains("* VANISHED (EARLIER) 1"), "{response}");

	// VANISHED without UID (plain FETCH) is rejected.
	let response = text(&session.command_line("a6 FETCH 1 (FLAGS) (CHANGEDSINCE 1 VANISHED)"));
	assert!(response.contains("a6 BAD"), "{response}");
}

#[test]
fn qresync_select_reports_vanished_uids() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());

	// First SELECT: capture UIDVALIDITY and the current HIGHESTMODSEQ.
	let response = text(&session.command_line("a2 SELECT INBOX"));
	let field = |key: &str| -> u64 {
		let after = response.split(&format!("[{key} ")).nth(1).expect("field");
		after
			.split(']')
			.next()
			.unwrap()
			.trim()
			.parse()
			.expect("number")
	};
	let validity = field("UIDVALIDITY");
	let modseq = field("HIGHESTMODSEQ");

	// Expunge message 1, then resync from the captured point.
	session.command_line("a3 STORE 1 +FLAGS (\\Deleted)");
	session.command_line("a4 EXPUNGE");
	let cmd = format!("a5 SELECT INBOX (QRESYNC ({validity} {modseq}))");
	let response = text(&session.command_line(&cmd));
	assert!(response.contains("* VANISHED (EARLIER) 1"), "{response}");

	// A mismatched UIDVALIDITY yields no VANISHED (the cache is moot).
	let cmd = format!("a6 SELECT INBOX (QRESYNC ({} {modseq}))", validity + 2);
	let response = text(&session.command_line(&cmd));
	assert!(!response.contains("VANISHED"), "{response}");

	assert!(
		text(&session.command_line("a7 CAPABILITY")).contains("QRESYNC"),
		"capability should advertise QRESYNC"
	);
}

#[test]
fn fetch_changedsince_filters_by_modseq() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\none\r\n");
	deliver(dir.path(), b"From: c@d\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	// Bump message 2's mod-sequence (now 2); message 1 stays at 1.
	session.command_line("a3 STORE 2 +FLAGS (\\Seen)");

	// CHANGEDSINCE 1 returns only message 2, and includes MODSEQ implicitly.
	let response = text(&session.command_line("a4 FETCH 1:2 (FLAGS) (CHANGEDSINCE 1)"));
	assert!(response.contains("* 2 FETCH"), "{response}");
	assert!(!response.contains("* 1 FETCH"), "{response}");
	assert!(response.contains("MODSEQ (2)"), "{response}");
}

#[test]
fn store_unchangedsince_reports_modified() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	// Advance the message's mod-sequence to 2.
	session.command_line("a3 STORE 1 +FLAGS (\\Flagged)");

	// UNCHANGEDSINCE 1 fails: the message changed since (modseq 2 > 1).
	let response = text(&session.command_line("a4 STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Seen)"));
	assert!(response.contains("[MODIFIED 1]"), "{response}");
	// The flag was not applied.
	let response = text(&session.command_line("a5 FETCH 1 (FLAGS)"));
	assert!(!response.contains("\\Seen"), "{response}");

	// UNCHANGEDSINCE with a high enough value succeeds and reports the new MODSEQ.
	let response = text(&session.command_line("a6 STORE 1 (UNCHANGEDSINCE 99) +FLAGS (\\Seen)"));
	assert!(response.contains("MODSEQ ("), "{response}");
	assert!(!response.contains("[MODIFIED"), "{response}");
	assert!(response.contains("\\Seen"), "{response}");
}

#[test]
fn condstore_reports_and_advances_modseq() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());

	// SELECT (CONDSTORE) is accepted and reports HIGHESTMODSEQ.
	let response = text(&session.command_line("a2 SELECT INBOX (CONDSTORE)"));
	assert!(response.contains("[HIGHESTMODSEQ "), "{response}");
	assert!(
		response.contains("a2 OK [READ-WRITE] SELECT completed"),
		"{response}"
	);

	// FETCH MODSEQ returns a parenthesized mod-sequence.
	let response = text(&session.command_line("a3 FETCH 1 (MODSEQ)"));
	assert!(response.contains("MODSEQ (1)"), "{response}");

	// A STORE advances the message's mod-sequence.
	session.command_line("a4 STORE 1 +FLAGS (\\Seen)");
	let response = text(&session.command_line("a5 FETCH 1 (MODSEQ)"));
	assert!(response.contains("MODSEQ (2)"), "{response}");

	// Capability advertises CONDSTORE.
	assert!(
		text(&session.command_line("a6 CAPABILITY")).contains("CONDSTORE"),
		"capability should advertise CONDSTORE"
	);
}

#[test]
fn append_stores_message_with_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let output = session.command_line(r"a2 APPEND INBOX (\Seen) {14}");
	assert_eq!(output.collect_literal, Some(14));
	assert!(text(&output).starts_with("+ "), "{}", text(&output));

	let output = session.literal_done(b"Subject: bye\r\n");
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	// UIDPLUS: the response carries the assigned UIDVALIDITY and UID 1.
	assert!(response.contains("[APPENDUID "), "{response}");
	assert!(response.contains(" 1] APPEND completed"), "{response}");

	// The appended message is visible on SELECT, with its flag.
	let output = session.command_line("a3 SELECT INBOX");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	let output = session.command_line("a4 FETCH 1 (FLAGS BODY[])");
	let response = text(&output);
	assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
	assert!(response.contains("Subject: bye"), "{response}");
}

#[test]
fn append_requires_authentication_and_known_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 APPEND INBOX {5}");
	assert!(text(&output).contains("a1 NO"));
	assert_eq!(output.collect_literal, None);

	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND Archive {5}");
	assert!(text(&output).contains("TRYCREATE"), "{}", text(&output));
}

#[test]
fn unexpected_literal_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.literal_done(b"stray");
	assert!(text(&output).contains("BAD"), "{}", text(&output));
}

#[test]
fn uid_expunge_removes_only_listed_deleted_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1:2 +FLAGS (\Deleted)");
	// UID EXPUNGE 1 removes only the message with UID 1.
	let response = text(&session.command_line("a4 UID EXPUNGE 1"));
	assert!(response.contains("* 1 EXPUNGE"), "{response}");
	assert!(response.contains("a4 OK EXPUNGE completed"), "{response}");
	// The second message (UID 2) survives, now at sequence 1.
	let response = text(&session.command_line("a5 FETCH 1 (UID)"));
	assert!(response.contains("UID 2"), "{response}");
}

#[test]
fn idle_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 IDLE");
	assert!(output.idle);
	assert!(text(&output).starts_with("+ "));
	let output = session.idle_done();
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));
	// A second DONE without IDLE is an error.
	let output = session.idle_done();
	assert!(text(&output).contains("BAD"));
}

#[test]
fn idle_requires_authentication() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 IDLE");
	assert!(text(&output).contains("a1 NO"));
	assert!(!output.idle);
}

#[test]
fn check_idle_detects_new_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line("a3 IDLE");
	assert!(output.idle, "should enter IDLE");

	// No change yet — check_idle returns None.
	assert!(session.check_idle().is_none());

	// Deliver a second message while idle.
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");

	// check_idle should now return an EXISTS notification.
	let notification = session.check_idle().expect("should get notification");
	let msg = text(&notification);
	assert!(msg.contains("* 2 EXISTS"), "{msg}");

	// Subsequent call returns None (no more changes).
	assert!(session.check_idle().is_none());
}

#[test]
fn check_idle_returns_none_when_not_idling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// Not in IDLE — should be None even if mailbox changes.
	assert!(session.check_idle().is_none());
	session.command_line("a2 SELECT INBOX");
	assert!(session.check_idle().is_none());
}

#[test]
fn notify_set_selected_returns_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output =
		session.command_line("a2 NOTIFY SET (selected (MessageNew MessageExpunge FlagChange))");
	assert!(text(&output).contains("a2 OK NOTIFY"), "{}", text(&output));
	assert!(session.notify_active());
}

#[test]
fn notify_none_returns_ok_and_disables() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 NOTIFY SET (selected (MessageNew))");
	assert!(session.notify_active());
	let output = session.command_line("a3 NOTIFY NONE");
	assert!(text(&output).contains("a3 OK NOTIFY"), "{}", text(&output));
	assert!(!session.notify_active());
}

#[test]
fn notify_malformed_returns_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 NOTIFY SET (selected (Bogus))");
	assert!(text(&output).contains("a2 BAD"), "{}", text(&output));
	assert!(!session.notify_active());
}

#[test]
fn notify_requires_authentication() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 NOTIFY SET (selected (MessageNew))");
	assert!(text(&output).contains("a1 NO"), "{}", text(&output));
}

#[test]
fn check_notify_pushes_exists_for_selected() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line("a3 NOTIFY SET (selected (MessageNew MessageExpunge))");

	// No change yet.
	assert!(session.check_notify().is_none());

	// Deliver while NOTIFY is active.
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");
	let notification = session.check_notify().expect("notification");
	assert!(
		text(&notification).contains("* 2 EXISTS"),
		"{}",
		text(&notification)
	);

	// Drained.
	assert!(session.check_notify().is_none());
}

#[test]
fn check_notify_none_when_not_enabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	// NOTIFY not set: no unsolicited push even though a message arrives.
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");
	assert!(session.check_notify().is_none());
}

#[test]
fn capability_advertises_notify_after_auth() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	// Pre-auth CAPABILITY must not advertise NOTIFY.
	let pre = text(&session.command_line("a1 CAPABILITY"));
	assert!(!pre.contains("NOTIFY"), "{pre}");
	session.command_line("a2 LOGIN alice secret");
	let post = text(&session.command_line("a3 CAPABILITY"));
	assert!(post.contains("NOTIFY"), "{post}");
}

#[test]
fn mailbox_lifecycle() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let output = session.command_line("a2 CREATE Sent");
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	// APPEND into the new mailbox works now.
	let output = session.command_line("a3 APPEND Sent {10}");
	assert_eq!(output.collect_literal, Some(10));
	let output = session.literal_done(b"sent body\n");
	assert!(text(&output).contains("a3 OK"), "{}", text(&output));

	let output = session.command_line("a4 SELECT Sent");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	session.command_line("a5 CLOSE");

	let output = session.command_line(r#"a6 LIST "" "*""#);
	let response = text(&output);
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("\"Sent\""), "{response}");

	let output = session.command_line("a7 RENAME Sent Outbox");
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
