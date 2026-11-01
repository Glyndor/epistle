//! THREAD=REFERENCES (RFC 5256 §3) through the session: Dovecot's imaptest
//! `thread` scripts, which mix the command with STORE and EXPUNGE, plus
//! UID THREAD, search criteria and the command's error paths. The
//! algorithm's own cases live with it in `thread_references/`.

use super::super::searching::sort_dates::append_mbox;
use super::*;

/// imaptest `thread.mbox`: the second message names the third as its
/// parent, and the third names the second.
const LOOP_MBOX: &str = "\
From user@domain  Fri Feb 22 17:06:23 2008
Message-ID: <a@b>

body

From user@domain  Fri Feb 22 15:06:23 2008
Message-Id: <b@b>
References: <a@b> <c@b>

body

From user@domain  Fri Feb 22 16:06:25 2008
Message-Id: <c@b>
References: <b@b>

body
";

/// imaptest `thread5.mbox`: a tree built from In-Reply-To alone.
const REPLY_TO_MBOX: &str = "\
From user@domain  Fri Feb 22 17:06:23 2008
Message-ID: <1@b>

body

From user@domain  Fri Feb 22 15:06:23 2008
Message-Id: <2@b>
In-Reply-To: <1@b>

body

From user@domain  Fri Feb 22 15:06:23 2008
Message-Id: <3@b>
In-Reply-To: <1@b>

body

From user@domain  Fri Feb 22 15:06:23 2008
Message-Id: <4@b>
In-Reply-To: <2@b>

body
";

/// The untagged reply of `command`, which must complete.
fn thread_line(session: &mut Session, command: &str) -> String {
	let response = text(&session.command_line(command));
	assert!(response.contains(" OK THREAD completed\r\n"), "{response}");
	response.lines().next().unwrap_or_default().to_string()
}

fn selected_with(mbox: &str) -> (tempfile::TempDir, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	append_mbox(&mut session, mbox);
	(dir, session)
}

fn expunge(session: &mut Session, set: &str) {
	let stored = text(&session.command_line(&format!("s STORE {set} +FLAGS (\\Deleted)")));
	assert!(stored.contains("s OK"), "{stored}");
	let expunged = text(&session.command_line("e EXPUNGE"));
	assert!(expunged.contains("e OK"), "{expunged}");
}

#[test]
fn imaptest_thread_before_and_after_an_expunge() {
	let (_dir, mut session) = selected_with(LOOP_MBOX);
	let command = "t THREAD REFERENCES US-ASCII ALL";
	assert_eq!(thread_line(&mut session, command), "* THREAD (3 2)(1)");
	expunge(&mut session, "1");
	assert_eq!(thread_line(&mut session, command), "* THREAD (2 1)");
	// The same threads by UID: the expunged message had UID 1.
	let by_uid = "u UID THREAD REFERENCES US-ASCII ALL";
	assert_eq!(thread_line(&mut session, by_uid), "* THREAD (3 2)");
}

#[test]
fn imaptest_thread5_with_in_reply_to() {
	let (_dir, mut session) = selected_with(REPLY_TO_MBOX);
	let command = "t THREAD REFERENCES US-ASCII ALL";
	assert_eq!(thread_line(&mut session, command), "* THREAD (1 (2 4)(3))");
	expunge(&mut session, "1,2");
	assert_eq!(thread_line(&mut session, command), "* THREAD (1)(2)");
}

#[test]
fn search_criteria_choose_the_messages_threaded() {
	let (_dir, mut session) = selected_with(REPLY_TO_MBOX);
	// Without message 1 its replies share a dummy parent.
	assert_eq!(
		thread_line(&mut session, "t THREAD REFERENCES UTF-8 2:4"),
		"* THREAD ((2 4)(3))"
	);
	assert_eq!(
		thread_line(&mut session, "t THREAD REFERENCES UTF-8 UID 1,4"),
		"* THREAD (4)(1)"
	);
	assert_eq!(
		thread_line(
			&mut session,
			"t THREAD REFERENCES UTF-8 HEADER Message-Id 9@b"
		),
		"* THREAD"
	);
}

#[test]
fn the_date_header_orders_before_the_internal_date() {
	// INTERNALDATE (the From_ line) says 1 is older; the Date headers
	// say 2 is, and RFC 5256 §2.2 sorts by the Date header.
	let mbox = "\
From user@domain  Fri Feb 22 10:00:00 2008
Message-ID: <a@b>
Date: Sat, 23 Feb 2008 10:00:00 +0000

body

From user@domain  Fri Feb 22 11:00:00 2008
Message-ID: <b@b>
Date: Thu, 21 Feb 2008 10:00:00 +0000

body
";
	let (_dir, mut session) = selected_with(mbox);
	assert_eq!(
		thread_line(&mut session, "t THREAD REFERENCES US-ASCII ALL"),
		"* THREAD (2)(1)"
	);
}

#[test]
fn an_empty_mailbox_has_no_threads() {
	let (_dir, mut session) = selected_with("");
	let response = text(&session.command_line("t THREAD REFERENCES US-ASCII ALL"));
	assert_eq!(response, "* THREAD\r\nt OK THREAD completed\r\n");
}

#[test]
fn thread_needs_a_mailbox_and_a_known_algorithm() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("t THREAD REFERENCES US-ASCII ALL"));
	assert_eq!(response, "t BAD no mailbox selected\r\n");
	session.command_line("a SELECT INBOX");
	let response = text(&session.command_line("t THREAD JWZ US-ASCII ALL"));
	assert!(response.starts_with("t BAD"), "{response}");
	let response = text(&session.command_line("t THREAD references us-ascii all"));
	assert_eq!(response, "* THREAD\r\nt OK THREAD completed\r\n");
}
