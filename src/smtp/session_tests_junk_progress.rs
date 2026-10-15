//! What counts against the junk-command limit and what does not. Commands
//! that never move a message (NOOP, RSET, VRFY, unknown verbs) count for
//! the whole session. Refused commands count only since the last message the session accepted: a
//! relay delivering a list with many unknown recipients across several
//! messages is not cut, while a client that only collects refusals is.

use super::tests_basic::{greeted, reply_code};
use super::tests_junk::{TOO_MANY, closing, send_kept};
use super::*;

/// Send one message to the known recipient and assert it is accepted.
fn deliver(session: &mut Session) {
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<list@lists.example.net>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	assert_eq!(reply_code(&session.command_line("DATA")), 354);
	assert!(session.data_line(b"Subject: hi").is_none());
	assert_eq!(reply_code(&session.data_line(b".").expect("end")), 250);
}

#[test]
fn a_list_with_many_unknown_recipients_is_not_cut_while_its_messages_are_accepted() {
	let mut session = greeted();
	for message in 0..3 {
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<list@lists.example.net>")),
			250
		);
		for unknown in 0..40 {
			let action =
				session.command_line(&format!("RCPT TO:<gone{message}x{unknown}@example.org>"));
			assert_eq!(
				closing(&action),
				None,
				"unknown recipient {unknown} of message {message} does not close the session"
			);
			assert_eq!(reply_code(&action), 550);
		}
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
			250
		);
		assert_eq!(reply_code(&session.command_line("DATA")), 354);
		assert!(session.data_line(b"Subject: list").is_none());
		assert_eq!(reply_code(&session.data_line(b".").expect("end")), 250);
	}
	assert_eq!(
		reply_code(&session.command_line("NOOP")),
		250,
		"120 unknown recipients over three accepted messages leave the session open"
	);
}

#[test]
fn refusals_without_an_accepted_message_close_the_session() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<probe@example.net>")),
		250
	);
	send_kept(&mut session, "RCPT TO:<guess@example.org>", 100);
	assert_eq!(
		closing(&session.command_line("RCPT TO:<guess@example.org>")).as_deref(),
		Some(TOO_MANY),
		"the 101st refusal with no message accepted is a scanner"
	);
}

#[test]
fn refusals_count_again_after_each_accepted_message() {
	let mut session = greeted();
	deliver(&mut session);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<probe@example.net>")),
		250
	);
	send_kept(&mut session, "RCPT TO:<guess@example.org>", 100);
	assert_eq!(
		closing(&session.command_line("RCPT TO:<guess@example.org>")).as_deref(),
		Some(TOO_MANY),
		"one accepted message buys 100 refusals, not an unlimited number"
	);
}
