//! BDAT chunks, NOTIFY and dot-stuffing.

use super::tests_basic::{greeted, reply_code};
use super::*;

#[test]
fn bdat_chunks_deliver_message() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<bob@example.org>");
	// First (non-final) chunk asks the network layer to read its bytes.
	let Action::CollectChunk { size, last } = session.command_line("BDAT 13") else {
		panic!("expected CollectChunk");
	};
	assert_eq!((size, last), (13, false));
	let cont = session.bdat_chunk(b"Subject: hi\r\n", false);
	assert_eq!(reply_code(&cont), 250);
	// Final chunk delivers the accumulated body verbatim (no dot-stuffing).
	let Action::CollectChunk { size, last } = session.command_line("BDAT 7 LAST") else {
		panic!("expected final CollectChunk");
	};
	assert_eq!((size, last), (7, true));
	let Action::Deliver(reply, message) = session.bdat_chunk(b"hello\r\n", true) else {
		panic!("expected delivery");
	};
	assert_eq!(reply.code(), 250);
	assert_eq!(message.data, b"Subject: hi\r\nhello\r\n");
	assert_eq!(message.recipients, vec!["bob@example.org".to_string()]);
}

#[test]
fn bdat_before_recipients_discards_then_rejects() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<alice@example.org>");
	// No RCPT yet: the chunk octets are still read (so they can't be parsed as
	// commands — RFC 3030), then the command is rejected with 503.
	// The chunk is read and thrown away without being kept.
	let action = session.command_line("BDAT 5 LAST");
	let Action::DiscardChunk { size, .. } = &action else {
		panic!("expected the chunk to be consumed before rejection");
	};
	assert_eq!(*size, 5);
	assert_eq!(reply_code(&action), 503);
}

#[test]
fn bdat_locks_out_data_and_rcpt() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<bob@example.org>");
	let Action::CollectChunk { .. } = session.command_line("BDAT 3") else {
		panic!("expected CollectChunk");
	};
	session.bdat_chunk(b"abc", false);
	// Once chunking has begun, DATA and further RCPT are invalid (RFC 3030).
	assert_eq!(reply_code(&session.command_line("DATA")), 503);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<c@example.org>")),
		503
	);
}

#[test]
fn bdat_over_max_chunk_aborts() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<bob@example.org>");
	let huge = MAX_MESSAGE_SIZE + 1;
	let action = session.command_line(&format!("BDAT {huge} LAST"));
	assert!(matches!(action, Action::Close(_)));
	assert_eq!(reply_code(&action), 552);
}

#[test]
fn notify_never_marks_recipient_no_dsn() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<alice@example.org>");
	// One recipient opts out of failure DSNs, the other keeps the default.
	session.command_line("RCPT TO:<bob@example.org> NOTIFY=NEVER");
	session.command_line("RCPT TO:<c@example.org> NOTIFY=SUCCESS,FAILURE");
	session.command_line("DATA");
	let Some(Action::Deliver(_, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(
		message.recipients,
		vec!["bob@example.org".to_string(), "c@example.org".to_string()]
	);
	// Only the NOTIFY=NEVER recipient suppresses its failure DSN.
	assert_eq!(message.no_dsn, vec!["bob@example.org".to_string()]);
}

#[test]
fn dot_stuffed_lines_are_unstuffed() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	assert_eq!(session.data_line(b"..leading dot"), None);
	let Some(Action::Deliver(_, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(message.data, b".leading dot\r\n");
}
