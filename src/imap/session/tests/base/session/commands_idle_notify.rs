//! IMAP session IDLE and NOTIFY command tests.

use super::*;
use crate::test_support::fixtures;

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
	session.command_line(&format!("a2 LOGIN alice {}", fixtures::password()));
	let post = text(&session.command_line("a3 CAPABILITY"));
	assert!(post.contains("NOTIFY"), "{post}");
}
