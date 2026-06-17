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
