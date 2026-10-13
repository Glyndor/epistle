//! NOTIFY SET STATUS reports the mailboxes it names (RFC 5465 §5.1).

use super::*;

fn session_with_box2() -> (tempfile::TempDir, Session, u32) {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: inbox\r\n\r\nbody\r\n");
	mailbox::create(dir.path(), "alice", "box2").expect("create");
	let crypto = crate::storage::MessageCrypto::disabled();
	mailbox::append(
		dir.path(),
		"alice",
		"box2",
		&[],
		b"Subject: x\r\n\r\ny\r\n",
		&crypto,
	)
	.expect("append");
	let snapshot = mailbox::Snapshot::open(dir.path(), "alice", "box2", &crypto).expect("open");
	let validity = snapshot.uid_validity();
	let session = logged_in(dir.path());
	(dir, session, validity)
}

#[test]
fn set_status_reports_each_named_mailbox() {
	let (_dir, mut session, validity) = session_with_box2();
	let output =
		session.command_line("n1 notify set status (mailboxes box2 (MessageNew MessageExpunge))");
	assert_eq!(
		text(&output),
		format!(
			"* STATUS \"box2\" (MESSAGES 1 UIDNEXT 2 UIDVALIDITY {validity})\r\nn1 OK NOTIFY completed\r\n"
		)
	);
	let output = session.command_line(
		"n2 notify set status (mailboxes box2 (MessageNew MessageExpunge FlagChange))",
	);
	assert_eq!(
		text(&output),
		format!(
			"* STATUS \"box2\" (MESSAGES 1 UIDNEXT 2 UIDVALIDITY {validity} HIGHESTMODSEQ 1)\r\n\
			 n2 OK NOTIFY completed\r\n"
		)
	);
}

#[test]
fn set_without_status_sends_no_status() {
	let (_dir, mut session, _) = session_with_box2();
	let output = session
		.command_line("n1 notify set (mailboxes box2 (MessageNew MessageExpunge FlagChange))");
	assert_eq!(text(&output), "n1 OK NOTIFY completed\r\n");
}

#[test]
fn set_status_skips_the_selected_and_missing_mailboxes() {
	let (_dir, mut session, _) = session_with_box2();
	session.command_line("s SELECT INBOX");
	let output = session.command_line(
		"n1 NOTIFY SET STATUS (personal (MessageNew)) (mailboxes nobox (MessageNew))",
	);
	let text = text(&output);
	assert!(text.contains("* STATUS \"box2\" (MESSAGES 1 "), "{text}");
	assert!(!text.contains("INBOX") && !text.contains("nobox"), "{text}");
}

#[test]
fn status_highestmodseq_item() {
	let (_dir, mut session, _) = session_with_box2();
	let output = session.command_line("s1 STATUS box2 (HIGHESTMODSEQ)");
	assert_eq!(
		text(&output),
		"* STATUS \"box2\" (HIGHESTMODSEQ 1)\r\ns1 OK STATUS completed\r\n"
	);
}
