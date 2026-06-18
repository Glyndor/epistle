//! Tests for the Sieve interpreter.

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

const MSG: &[u8] =
	b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: Big SALE today\r\n\r\nbuy\r\n";

fn run(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(raw))
}

#[test]
fn empty_script_keeps_implicitly() {
	let outcome = run("", MSG);
	assert!(outcome.keep);
	assert!(outcome.fileinto.is_empty());
}

#[test]
fn fileinto_cancels_implicit_keep() {
	let outcome = run("fileinto \"Archive\";", MSG);
	assert!(!outcome.keep);
	assert_eq!(outcome.fileinto, vec!["Archive".to_string()]);
}

#[test]
fn explicit_keep_with_fileinto_keeps_both() {
	let outcome = run("fileinto \"Archive\"; keep;", MSG);
	assert!(outcome.keep);
	assert_eq!(outcome.fileinto, vec!["Archive".to_string()]);
}

#[test]
fn discard_drops_the_message() {
	let outcome = run("discard;", MSG);
	assert!(!outcome.keep);
	assert!(outcome.discarded);
}

#[test]
fn fileinto_copy_preserves_implicit_keep() {
	// `:copy` (RFC 3894): the message is filed AND kept in the inbox.
	let outcome = run("fileinto :copy \"Archive\";", MSG);
	assert!(outcome.keep, "{outcome:?}");
	assert_eq!(outcome.fileinto, vec!["Archive".to_string()]);

	// redirect :copy likewise keeps the inbox copy.
	let outcome = run("redirect :copy \"forward@example.com\";", MSG);
	assert!(outcome.keep, "{outcome:?}");
	assert_eq!(outcome.redirects, vec!["forward@example.com".to_string()]);

	// Without :copy the implicit keep is still cancelled.
	let outcome = run("fileinto \"Archive\";", MSG);
	assert!(!outcome.keep);
}

#[test]
fn imap4flags_set_add_and_remove() {
	// setflag replaces, addflag unions, removeflag subtracts (RFC 5232).
	let outcome = run(
		"setflag \"\\\\Seen \\\\Flagged\"; addflag \"\\\\Answered\"; removeflag \"\\\\Flagged\";",
		MSG,
	);
	assert!(
		outcome.flags.contains(&"\\Seen".to_string()),
		"{:?}",
		outcome.flags
	);
	assert!(
		outcome.flags.contains(&"\\Answered".to_string()),
		"{:?}",
		outcome.flags
	);
	assert!(
		!outcome.flags.contains(&"\\Flagged".to_string()),
		"{:?}",
		outcome.flags
	);
}

#[test]
fn header_contains_files_into_junk() {
	let script = "if header :contains \"Subject\" \"sale\" { fileinto \"Junk\"; }";
	let outcome = run(script, MSG);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
	assert!(!outcome.keep);
}

#[test]
fn header_is_requires_exact_value() {
	let hit = run("if header :is \"To\" \"bob@example.net\" { discard; }", MSG);
	assert!(hit.discarded);
	let miss = run("if header :is \"To\" \"bob\" { discard; }", MSG);
	assert!(!miss.discarded);
}

#[test]
fn matches_uses_wildcards() {
	let outcome = run(
		"if header :matches \"Subject\" \"Big*today\" { discard; }",
		MSG,
	);
	assert!(outcome.discarded);
}

#[test]
fn size_over_and_under() {
	let over = run("if size :over 10 { discard; }", MSG);
	assert!(over.discarded);
	let under = run("if size :under 10 { discard; }", MSG);
	assert!(!under.discarded);
}

#[test]
fn exists_test() {
	let yes = run("if exists [\"From\", \"Subject\"] { fileinto \"X\"; }", MSG);
	assert_eq!(yes.fileinto, vec!["X".to_string()]);
	let no = run("if exists \"Reply-To\" { fileinto \"X\"; }", MSG);
	assert!(no.fileinto.is_empty());
}

#[test]
fn allof_anyof_not_combinators() {
	let allof = run(
		"if allof (exists \"From\", header :contains \"Subject\" \"sale\") { discard; }",
		MSG,
	);
	assert!(allof.discarded);
	let anyof = run(
		"if anyof (exists \"Reply-To\", header :is \"To\" \"bob@example.net\") { discard; }",
		MSG,
	);
	assert!(anyof.discarded);
	let not = run("if not exists \"Reply-To\" { discard; }", MSG);
	assert!(not.discarded);
}

#[test]
fn address_test_matches_parts() {
	// Header value with a display name and angle-addr.
	let msg = b"From: Alice <alice@example.org>\r\nTo: bob@example.net\r\n\r\nx\r\n";
	let all = run(
		"if address :is \"From\" \"alice@example.org\" { discard; }",
		msg,
	);
	assert!(all.discarded);
	let local = run(
		"if address :localpart :is \"From\" \"alice\" { discard; }",
		msg,
	);
	assert!(local.discarded);
	let domain = run(
		"if address :domain :is \"From\" \"example.org\" { discard; }",
		msg,
	);
	assert!(domain.discarded);
	// Bare address (no display name) still parses.
	let bare = run(
		"if address :domain :is \"To\" \"example.net\" { discard; }",
		msg,
	);
	assert!(bare.discarded);
	// Wrong value does not match.
	let miss = run(
		"if address :is \"From\" \"eve@example.org\" { discard; }",
		msg,
	);
	assert!(!miss.discarded);
}

#[test]
fn envelope_test_matches_mail_from_and_rcpt_to() {
	let tokens =
		tokenize("if envelope :domain :is \"from\" \"bad.example\" { discard; }").expect("lex");
	let commands = parse(&tokens).expect("parse");
	let msg = Message::parse(MSG).with_envelope(
		"spammer@bad.example".to_string(),
		vec!["bob@example.net".to_string()],
	);
	assert!(evaluate(&commands, &msg).discarded);

	let to =
		parse(&tokenize("if envelope :localpart :is \"to\" \"bob\" { discard; }").expect("lex"))
			.expect("parse");
	assert!(evaluate(&to, &msg).discarded);

	// Without a matching envelope it does not fire.
	let miss = parse(&tokenize("if envelope :is \"from\" \"x@y\" { discard; }").unwrap()).unwrap();
	assert!(!evaluate(&miss, &msg).discarded);
}

#[test]
fn envelope_absent_never_matches() {
	let commands =
		parse(&tokenize("if envelope :is \"from\" \"a@b\" { discard; }").unwrap()).unwrap();
	// No envelope attached: the test is simply false, mail keeps.
	let outcome = evaluate(&commands, &Message::parse(MSG));
	assert!(!outcome.discarded);
	assert!(outcome.keep);
}

#[test]
fn body_test_matches_content() {
	let msg = b"Subject: hi\r\n\r\nClaim your free LOTTERY prize now\r\n";
	let hit = run("if body :contains \"lottery\" { discard; }", msg);
	assert!(hit.discarded);
	let miss = run("if body :contains \"invoice\" { discard; }", msg);
	assert!(!miss.discarded);
	// :text behaves the same (no MIME decoding yet).
	let text = run("if body :text :contains \"prize\" { discard; }", msg);
	assert!(text.discarded);
}

#[test]
fn date_test_matches_header_parts() {
	let msg = b"Date: Wed, 17 Jun 2026 14:30:05 +0000\r\nSubject: hi\r\n\r\nbody\r\n";
	// The Date header's year matches.
	let hit = run("if date \"Date\" \"year\" \"2026\" { discard; }", msg);
	assert!(hit.discarded);
	// A wrong month does not match.
	let miss = run("if date \"Date\" \"month\" \"12\" { discard; }", msg);
	assert!(!miss.discarded);
	// :is on the assembled date.
	let date = run(
		"if date :is \"Date\" \"date\" \"2026-06-17\" { discard; }",
		msg,
	);
	assert!(date.discarded);
}

#[test]
fn stop_halts_execution() {
	let outcome = run("fileinto \"A\"; stop; fileinto \"B\";", MSG);
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
}

#[test]
fn redirect_records_address() {
	let outcome = run("redirect \"forward@example.com\";", MSG);
	assert_eq!(outcome.redirects, vec!["forward@example.com".to_string()]);
	assert!(!outcome.keep);
}

#[test]
fn elsif_else_chain() {
	let script = "if size :over 100000 { fileinto \"Big\"; } \
elsif header :contains \"Subject\" \"sale\" { fileinto \"Junk\"; } \
else { keep; }";
	let outcome = run(script, MSG);
	assert_eq!(outcome.fileinto, vec!["Junk".to_string()]);
}
