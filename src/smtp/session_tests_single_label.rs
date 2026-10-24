//! The single-label domain rule at the SMTP surface.
//!
//! A domain of one label (`localhost`, `intranet`) is a legal RFC 5321
//! mailbox, but RFC 5321 section 2.3.5 says only fully qualified names
//! appear in an SMTP transaction, so mail for it never reaches the public
//! internet. The envelope is where a single-label domain would enter the
//! server, and both envelope commands refuse one.
//!
//! The two cases RFC 5321 section 4.5.1 carves out are recorded here as
//! they are answered today, so a change to either one is visible.

use super::*;

/// A session over a directory that serves one domain, with the recipient
/// the tests need.
fn session() -> Session {
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session
}

/// The code and the text of a reply, so a refusal can be read and not only
/// counted.
fn reply(action: &Action) -> (u16, String) {
	let text = match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::DiscardChunk { reply: r, .. } => r.to_string(),
		Action::Deliver(r, _) => r.to_string(),
		// A BDAT chunk read carries no reply.
		Action::CollectChunk { .. } => String::new(),
	};
	let code = match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::DiscardChunk { reply: r, .. } => r.code(),
		Action::Deliver(r, _) => r.code(),
		Action::CollectChunk { .. } => 0,
	};
	(code, text)
}

/// `MAIL FROM:<user@localhost>` is refused: the reverse path must be an
/// address of a domain with at least one dot.
#[test]
fn a_single_label_reverse_path_is_refused() {
	let mut session = session();
	let (code, text) = reply(&session.command_line("MAIL FROM:<user@localhost>"));
	assert_eq!(code, 553);
	assert!(
		text.contains("5.1.7"),
		"the refusal names the reverse-path code: {text}"
	);
}

/// `RCPT TO:<user@localhost>` is refused for the same reason.
#[test]
fn a_single_label_recipient_is_refused() {
	let mut session = session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let (code, text) = reply(&session.command_line("RCPT TO:<user@localhost>"));
	assert_eq!(code, 553);
	assert!(
		text.contains("5.1.3"),
		"the refusal names the recipient code: {text}"
	);
}

/// A single-label domain in the reverse path of an inbound message never
/// reaches the queue: the envelope is refused before DATA.
#[test]
fn a_single_label_sender_never_reaches_the_queue() {
	let mut session = session();
	let (code, _) = reply(&session.command_line("MAIL FROM:<user@intranet>"));
	assert_eq!(code, 553);
	// The session never opened a transaction, so DATA is out of sequence.
	let (code, _) = reply(&session.command_line("DATA"));
	assert_eq!(code, 503);
}

/// RFC 5321 section 4.5.1: the reserved mailbox `postmaster` may be used in
/// a RCPT command without a domain, and the server must accept it. epistle
/// refuses it today, because the address parser wants an `@`; the case is
/// recorded here so the deviation is visible and not mistaken for the rule
/// this file is about.
#[test]
fn the_domain_less_postmaster_is_refused_today() {
	let mut session = session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let (code, text) = reply(&session.command_line("RCPT TO:<postmaster>"));
	assert_eq!(code, 553);
	assert!(
		text.contains("5.1.3"),
		"the refusal names the recipient code: {text}"
	);
}

/// The same reserved mailbox in the reverse path has no exception:
/// RFC 5321 section 4.5.1 carves the domain-less form out for RCPT only.
#[test]
fn the_domain_less_postmaster_is_refused_as_a_reverse_path() {
	let mut session = session();
	let (code, text) = reply(&session.command_line("MAIL FROM:<postmaster>"));
	assert_eq!(code, 553);
	assert!(
		text.contains("5.1.7"),
		"the refusal names the reverse-path code: {text}"
	);
}
