//! Tests for the `mailbox` extension (RFC 5490): the `mailboxexists` test
//! against the account's mailbox list, the `:create` tag of `fileinto`,
//! and the runtime `require` check the validator imposes.

use super::super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::super::parser::parse;

const MSG: &[u8] = b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nbody\r\n";

fn run(script: &str, raw: &[u8], mailboxes: &[&str]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	let mut owned: Vec<String> = mailboxes.iter().map(|m| m.to_string()).collect();
	let message = Message::parse(raw)
		.with_envelope(
			"sender@elsewhere.example",
			vec!["alice@example.org".to_string()],
		)
		.with_mailboxes(&mut owned);
	evaluate(&commands, &message)
}

#[test]
fn mailboxexists_true_when_named_folder_is_in_the_account() {
	let outcome = run(
		"require \"mailbox\"; if mailboxexists \"Junk\" { fileinto \"Junk\"; }",
		MSG,
		&["INBOX", "Junk"],
	);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
	assert!(
		!outcome.keep,
		"the implicit keep is cancelled by the fileinto"
	);
}

#[test]
fn mailboxexists_is_false_when_the_folder_is_missing() {
	let outcome = run(
		"require \"mailbox\"; if mailboxexists \"Junk\" { fileinto \"Junk\"; }",
		MSG,
		&["INBOX"],
	);
	assert!(outcome.fileinto.is_empty());
	assert!(outcome.keep, "no fileinto: the implicit keep stands");
}

#[test]
fn mailboxexists_inbox_is_always_true() {
	// INBOX is implicit and need not be listed in the message's mailboxes.
	let outcome = run(
		"require \"mailbox\"; if mailboxexists \"INBOX\" { fileinto \"Archive\"; }",
		MSG,
		&["Archive"],
	);
	assert_eq!(outcome.fileinto, vec!["Archive".to_string()]);
}

#[test]
fn mailboxexists_requires_every_name_to_exist() {
	let outcome = run(
		"require \"mailbox\"; \
		 if mailboxexists [\"Junk\", \"Archive\"] { fileinto \"Archive\"; }",
		MSG,
		&["INBOX", "Junk", "Archive"],
	);
	assert_eq!(outcome.fileinto, vec!["Archive".to_string()]);

	let partial = run(
		"require \"mailbox\"; \
		 if mailboxexists [\"Junk\", \"Archive\"] { fileinto \"Archive\"; }",
		MSG,
		&["INBOX", "Junk"],
	);
	assert!(partial.fileinto.is_empty());
}

#[test]
fn mailboxexists_uses_modified_utf7_for_the_name() {
	// The on-disk spelling of "Año" is "A&APE-o" (modified UTF-7). The
	// script author writes the UTF-8 spelling; the interpreter looks up
	// the on-disk form, mirroring how `fileinto` resolves folder names.
	let outcome = run(
		"require \"mailbox\"; if mailboxexists \"Año\" { fileinto \"Año\"; }",
		MSG,
		&["INBOX", "A&APE-o"],
	);
	assert_eq!(
		outcome.fileinto,
		vec!["Año".to_string()],
		"fileinto keeps the script's UTF-8 spelling; the delivery side \
		 encodes to the IMAP on-disk form"
	);
	assert!(
		outcome.fileinto_creates.is_empty(),
		"no :create tag, so no folder creation"
	);
}

#[test]
fn mailboxexists_with_no_mailbox_set_is_false() {
	// The interpreter does not crash on a missing mailbox set; it fails safe
	// to "does not exist", as it did before the extension existed.
	let outcome = run(
		"require \"mailbox\"; if mailboxexists \"Junk\" { fileinto \"Junk\"; }",
		MSG,
		&[],
	);
	assert!(outcome.fileinto.is_empty());
	assert!(outcome.keep);
}

#[test]
fn fileinto_create_marks_the_folder_for_creation() {
	let outcome = run("require \"mailbox\"; fileinto :create \"Junk\";", MSG, &[]);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
	assert!(
		outcome.fileinto_creates.contains("Junk"),
		"fileinto :create must record Junk as needing creation; got {:?}",
		outcome.fileinto_creates
	);
}

#[test]
fn fileinto_without_create_does_not_mark_for_creation() {
	let outcome = run("fileinto \"Junk\";", MSG, &[]);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
	assert!(
		!outcome.fileinto_creates.contains("Junk"),
		"a plain fileinto must not request creation; got {:?}",
		outcome.fileinto_creates
	);
}

#[test]
fn fileinto_create_combines_with_copy() {
	// :copy and :create are independent tags (RFC 5490 3.2, RFC 3894 3).
	let outcome = run(
		"require \"mailbox\"; fileinto :copy :create \"Junk\";",
		MSG,
		&[],
	);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
	assert!(outcome.fileinto_creates.contains("Junk"));
	assert!(outcome.keep, ":copy keeps the implicit keep");
}
