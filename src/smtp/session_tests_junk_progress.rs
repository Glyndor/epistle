//! What counts against the junk-command limit and what does not. Commands
//! that never move a message (NOOP, RSET, VRFY, unknown verbs, a repeated
//! greeting, an empty BDAT chunk) count for the whole session. Refused
//! commands count only since the last message the server accepted: a
//! relay delivering a list with many unknown recipients across several
//! messages is not cut, while a client that only collects refusals is.

use super::tests_basic::{greeted, reply_code};
use super::tests_junk::{TOO_MANY, closing, send_kept};
use super::*;

/// Send one message to the known recipient, accepted by the session and
/// then by the server.
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
	session.message_delivered();
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
		// The connection loop reports the message handed on.
		session.message_delivered();
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

#[test]
fn a_repeated_greeting_counts() {
	let mut session = greeted();
	send_kept(&mut session, "EHLO client.example.org", 50);
	send_kept(&mut session, "HELO client.example.org", 50);
	assert_eq!(
		closing(&session.command_line("EHLO client.example.org")).as_deref(),
		Some(TOO_MANY),
		"the 101st greeting after the first one closes the session"
	);
}

#[test]
fn the_first_greeting_inside_tls_is_not_junk() {
	let mut session = greeted();
	session.tls_started();
	assert_eq!(
		reply_code(&session.command_line("EHLO client.example.org")),
		250
	);
	send_kept(&mut session, "NOOP", 100);
	assert_eq!(
		closing(&session.command_line("NOOP")).as_deref(),
		Some(TOO_MANY),
		"the two required greetings cost nothing: the 101st NOOP is the cut"
	);
}

#[test]
fn empty_bdat_chunks_inside_a_transaction_count() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.net>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	for chunk in 1..=100 {
		let action = session.command_line("BDAT 0");
		assert!(
			matches!(
				action,
				Action::CollectChunk {
					size: 0,
					last: false
				}
			),
			"empty chunk {chunk} is read"
		);
		assert_eq!(reply_code(&session.bdat_chunk(b"", false)), 250);
	}
	assert_eq!(
		closing(&session.command_line("BDAT 0")).as_deref(),
		Some(TOO_MANY),
		"the 101st empty chunk closes the session"
	);
}
