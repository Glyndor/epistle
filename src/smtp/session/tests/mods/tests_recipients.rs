//! `max_recipients` on a session: the cap the operator sets is the one
//! `RCPT TO` enforces and `EHLO` advertises.

use super::tests_basic::reply_code;
use super::*;

fn directory(count: usize) -> Arc<Directory> {
	let entries: Vec<(String, String)> = (0..=count)
		.map(|index| (format!("r{index}@example.org"), "bob".to_string()))
		.collect();
	Arc::new(Directory::new(["example.org".to_string()], entries))
}

fn session_with_cap(cap: usize, directory_size: usize) -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(directory(directory_size))
		.with_max_recipients(cap);
	session.command_line("EHLO client.example.org");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		250
	);
	session
}

#[test]
fn a_raised_cap_takes_that_many_recipients_and_refuses_the_next() {
	let mut session = session_with_cap(500, 501);
	for index in 0..500 {
		let action = session.command_line(&format!("RCPT TO:<r{index}@example.org>"));
		assert_eq!(reply_code(&action), 250, "recipient {index} accepted");
	}
	let Action::Continue(reply) = session.command_line("RCPT TO:<r500@example.org>") else {
		panic!("the recipient over the cap is answered, not collected");
	};
	assert_eq!(reply.to_string(), "452 4.5.3 too many recipients\r\n");
}

#[test]
fn a_cap_of_one_hundred_still_refuses_the_hundred_and_first() {
	let mut session = session_with_cap(100, 101);
	for index in 0..100 {
		let action = session.command_line(&format!("RCPT TO:<r{index}@example.org>"));
		assert_eq!(reply_code(&action), 250, "recipient {index} accepted");
	}
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<r100@example.org>")),
		452
	);
}

#[test]
fn ehlo_advertises_the_configured_cap() {
	let mut session = Session::new("mail.example.org").with_max_recipients(500);
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("EHLO is answered");
	};
	let rendered = reply.to_string();
	let advertised = rendered.lines().find(|line| line.contains("LIMITS"));
	assert_eq!(
		advertised,
		Some("250 LIMITS RCPTMAX=500"),
		"EHLO advertises the cap the session enforces"
	);
}

#[test]
fn a_cap_of_zero_keeps_the_default() {
	let session = Session::new("mail.example.org").with_max_recipients(0);
	assert_eq!(session.max_recipients(), DEFAULT_MAX_RECIPIENTS);
	assert_eq!(DEFAULT_MAX_RECIPIENTS, 100);
}
