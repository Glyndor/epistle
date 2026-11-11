//! A FETCH answer is built in memory, so it stops at a cap and tells the
//! client to ask for the rest.

use super::{deliver, logged_in};

fn mailbox_of(messages: usize, size: usize) -> (tempfile::TempDir, super::Session) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let body = vec![b'x'; size];
	let raw = [b"Subject: big\r\n\r\n".as_slice(), body.as_slice()].concat();
	for _ in 0..messages {
		deliver(dir.path(), &raw);
	}
	let mut session = logged_in(dir.path());
	session.command_line("s SELECT INBOX");
	(dir, session)
}

fn count(text: &str, needle: &str) -> usize {
	text.matches(needle).count()
}

#[test]
fn a_fetch_over_the_cap_stops_between_messages_and_answers_no_limit() {
	let (_dir, mut session) = mailbox_of(10, 1000);
	session.fetch_response_limit = 2500;
	let text = String::from_utf8(session.command_line("f FETCH 1:* (BODY.PEEK[])").bytes).unwrap();
	// Three messages (each about 1 KiB) bring the answer past 2500 octets.
	assert_eq!(count(&text, " FETCH (BODY[]"), 3, "{text}");
	assert!(
		text.ends_with(
			"f NO [LIMIT] FETCH answer too large, fetch the remaining messages in another command\r\n"
		),
		"the tagged answer must be NO [LIMIT]: {}",
		text.lines().last().unwrap_or_default()
	);
}

#[test]
fn the_first_message_is_sent_whole_even_when_it_alone_is_over_the_cap() {
	let (_dir, mut session) = mailbox_of(3, 1000);
	session.fetch_response_limit = 10;
	let text = String::from_utf8(session.command_line("f FETCH 1:* (BODY.PEEK[])").bytes).unwrap();
	assert_eq!(count(&text, " FETCH (BODY[]"), 1, "{text}");
	assert!(text.contains("f NO [LIMIT]"), "{text}");
}

#[test]
fn a_fetch_under_the_cap_completes() {
	let (_dir, mut session) = mailbox_of(3, 100);
	let text = String::from_utf8(session.command_line("f FETCH 1:* (BODY.PEEK[])").bytes).unwrap();
	assert_eq!(count(&text, " FETCH (BODY[]"), 3, "{text}");
	assert!(text.ends_with("f OK FETCH completed\r\n"), "{text}");
}
