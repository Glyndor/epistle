//! A mailbox deleted and created again gets a new UIDVALIDITY (RFC 9051
//! §2.3.1.1), even within the same second.

use super::*;

fn status(session: &mut Session, tag: &str) -> String {
	text(&session.command_line(&format!("{tag} STATUS box (UIDVALIDITY UIDNEXT)")))
}

#[test]
fn recreated_mailbox_has_a_new_uidvalidity() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: inbox\r\n\r\nbody\r\n");
	let crypto = crate::storage::MessageCrypto::disabled();
	let mut session = logged_in(dir.path());
	assert!(text(&session.command_line("c1 CREATE box")).contains("c1 OK"));
	mailbox::append(
		dir.path(),
		"alice",
		"box",
		&[],
		b"Subject: 1\r\n\r\nx\r\n",
		&crypto,
	)
	.expect("append");
	let before = status(&mut session, "s1");
	assert!(text(&session.command_line("d1 DELETE box")).contains("d1 OK"));
	assert!(text(&session.command_line("c2 CREATE box")).contains("c2 OK"));
	mailbox::append(
		dir.path(),
		"alice",
		"box",
		&[],
		b"Subject: 2\r\n\r\nx\r\n",
		&crypto,
	)
	.expect("append");
	let after = status(&mut session, "s2");
	assert!(after.contains("UIDNEXT 2"), "{after}");
	assert_ne!(before.replace("s1 ", ""), after.replace("s2 ", ""));
}
