//! RSET, declared sizes and message size limits, and connection-level commands.

use super::tests_basic::{greeted, reply_code, test_directory};
use super::*;

#[test]
fn rset_aborts_transaction() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("RSET")), 250);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
		250
	);
}

#[test]
fn declared_size_within_limit_is_accepted() {
	let mut session = greeted();
	let action = session.command_line(&format!(
		"MAIL FROM:<a@example.org> SIZE={} BODY=8BITMIME",
		MAX_MESSAGE_SIZE
	));
	assert_eq!(reply_code(&action), 250);
}

#[test]
fn declared_oversize_is_rejected_at_mail_time() {
	let mut session = greeted();
	let action = session.command_line(&format!(
		"MAIL FROM:<a@example.org> SIZE={}",
		MAX_MESSAGE_SIZE as u64 + 1
	));
	assert_eq!(reply_code(&action), 552);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		503
	);
}

/// The per-instance message-size cap is what the operator sets in
/// `max_message_size`; the SMTP `SIZE` extension, MAIL FROM
/// SIZE parameter, the per-line running check, the end-of-DATA check,
/// and the BDAT per-chunk cap all share the same value. Lowering the
/// cap on one session must shrink every check at once: a size the
/// default would have accepted is now refused with `552 5.3.4`.
#[test]
fn configured_max_message_size_applies_to_smtp_size_end_of_data_and_bdat() {
	let cap = 1024;
	let mut session = Session::new("mail.example.org")
		.with_directory(test_directory())
		.with_max_message_size(cap);
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("EHLO");
	};
	// EHLO advertises the configured cap, not the historical default:
	// the wire shows the operator's number end to end.
	assert!(
		reply.to_string().contains(&format!("SIZE {cap}")),
		"EHLO SIZE line must carry the configured cap"
	);
	// SIZE parameter above the configured cap is refused at MAIL FROM.
	let oversize = session.command_line(&format!("MAIL FROM:<a@example.org> SIZE={}", cap + 1));
	assert_eq!(reply_code(&oversize), 552);
	// SIZE at the cap itself is admitted.
	let at_cap = session.command_line(&format!("MAIL FROM:<a@example.org> SIZE={cap}"));
	assert_eq!(reply_code(&at_cap), 250);
	// A fresh session with the same cap refuses a BDAT chunk over it.
	let mut bdat_session = Session::new("mail.example.org")
		.with_directory(test_directory())
		.with_max_message_size(cap);
	bdat_session.command_line("EHLO client.example.org");
	bdat_session.command_line("MAIL FROM:<a@example.org>");
	bdat_session.command_line("RCPT TO:<b@example.org>");
	let action = bdat_session.command_line(&format!("BDAT {} LAST", cap + 1));
	assert_eq!(
		reply_code(&action),
		552,
		"BDAT over the configured cap must be refused with 552"
	);
}

#[test]
fn unsupported_parameter_gets_555() {
	let mut session = greeted();
	let action = session.command_line("MAIL FROM:<a@example.org> AUTH=<>");
	assert_eq!(reply_code(&action), 555);
}

#[test]
fn quit_closes_connection() {
	let mut session = greeted();
	let action = session.command_line("QUIT");
	assert!(matches!(action, Action::Close(_)));
	assert_eq!(reply_code(&action), 221);
}

#[test]
fn vrfy_discloses_nothing() {
	let mut session = greeted();
	assert_eq!(reply_code(&session.command_line("VRFY alice")), 252);
}

#[test]
fn unknown_command_gets_500() {
	let mut session = greeted();
	assert_eq!(reply_code(&session.command_line("EXPN staff")), 500);
}

#[test]
fn oversize_message_is_rejected_and_not_delivered() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	let chunk = "x".repeat(1024);
	let lines_needed = MAX_MESSAGE_SIZE / chunk.len() + 1;
	for _ in 0..lines_needed {
		assert_eq!(session.data_line(chunk.as_bytes()), None);
	}
	let Some(action) = session.data_line(b".") else {
		panic!("expected final action");
	};
	assert_eq!(reply_code(&action), 552);
	assert!(matches!(action, Action::Continue(_)));
}

#[test]
fn data_line_outside_data_state_fails_closed() {
	let mut session = greeted();
	let action = session.data_line(b"stray");
	assert_eq!(action.map(|a| reply_code(&a)), Some(503));
}

#[test]
fn second_transaction_works_after_delivery() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	session.data_line(b"first");
	assert!(matches!(session.data_line(b"."), Some(Action::Deliver(..))));

	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
		250
	);
}
