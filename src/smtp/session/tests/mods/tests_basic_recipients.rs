//! Command order and recipient acceptance rules.

use super::tests_basic::{greeted, reply_code};
use super::*;

#[test]
fn mail_before_greeting_is_rejected() {
	let mut session = Session::new("mail.example.org");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		503
	);
}

#[test]
fn rcpt_without_mail_is_rejected() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		503
	);
}

#[test]
fn data_without_recipients_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("DATA")), 503);
}

#[test]
fn empty_recipient_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("RCPT TO:<>")), 553);
}

#[test]
fn malformed_recipient_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<no-at-sign>")),
		553
	);
}

#[test]
fn non_local_recipient_is_denied() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	let action = session.command_line("RCPT TO:<b@elsewhere.example>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn recipient_domain_match_is_case_insensitive() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@EXAMPLE.ORG>")),
		250
	);
}

#[test]
fn unknown_user_in_local_domain_is_denied() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	let action = session.command_line("RCPT TO:<stranger@example.org>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn postmaster_address_is_accepted() {
	// RFC 5321 §4.5.1 MUST: mail to `postmaster@<domain>` is accepted. With
	// the address owned by `bob`, RCPT TO returns 250 and the recipient is
	// recorded as `postmaster@example.org` for delivery.
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("postmaster@example.org".to_string(), "bob".to_string()),
		],
	));
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<postmaster@example.org>")),
		250
	);
}

#[test]
fn postmaster_address_is_accepted_case_insensitively() {
	// The address parser lowercases the domain (and the directory lookup is
	// case-insensitive), so `POSTMASTER@EXAMPLE.ORG` resolves exactly like
	// the canonical form.
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[("postmaster@example.org".to_string(), "bob".to_string())],
	));
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<POSTMASTER@EXAMPLE.ORG>")),
		250
	);
}

#[test]
fn postmaster_unconfigured_in_local_domain_is_denied() {
	// Mirror of `unknown_user_in_local_domain_is_denied` for the postmaster
	// local part specifically: without an explicit address or a catch-all
	// for the domain, postmaster falls through to `UnknownUser` and is
	// rejected. The validator at config time is what prevents this from
	// reaching a real server.
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	let action = session.command_line("RCPT TO:<postmaster@example.org>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn abuse_address_is_accepted_when_configured() {
	// RFC 2142 lists `abuse@<domain>` as a SHOULD; when the operator
	// configures it as an explicit address, RCPT TO returns 250 just like
	// any other local account.
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("abuse@example.org".to_string(), "bob".to_string()),
		],
	));
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<abuse@example.org>")),
		250
	);
}

#[test]
fn without_local_domains_every_recipient_is_denied() {
	let mut session = Session::new("mail.example.org");
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		550
	);
}

#[test]
fn malformed_reverse_path_is_rejected() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<not-an-address>")),
		553
	);
	// Null reverse-path stays legal for bounces.
	assert_eq!(reply_code(&session.command_line("MAIL FROM:<>")), 250);
}

#[test]
fn recipient_limit_is_enforced() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	for i in 0..DEFAULT_MAX_RECIPIENTS {
		let action = session.command_line(&format!("RCPT TO:<r{i}@example.org>"));
		assert_eq!(reply_code(&action), 250, "recipient {i} accepted");
	}
	let action = session.command_line("RCPT TO:<overflow@example.org>");
	assert_eq!(reply_code(&action), 452);
}
