//! How many forwards one run of a script may ask for.

use super::interp::{MAX_REDIRECTS, Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

const MSG: &[u8] = b"From: a@example.org\r\nTo: b@example.net\r\nSubject: hi\r\n\r\nx\r\n";

fn run(script: &str) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(MSG))
}

#[test]
fn a_script_cannot_ask_for_more_forwards_than_the_limit() {
	// A script of 15 000 distinct redirects is a few hundred kilobytes, well
	// inside what a user may upload. One inbound message would otherwise fan
	// out into 30 000 outbound ones.
	let script: String = (0..15_000)
		.map(|n| format!("redirect \"user{n}@target.example\";\n"))
		.collect();
	let outcome = run(&script);
	assert_eq!(outcome.redirects.len(), MAX_REDIRECTS);
	let first: Vec<String> = (0..MAX_REDIRECTS)
		.map(|n| format!("user{n}@target.example"))
		.collect();
	assert_eq!(
		outcome.redirects, first,
		"the first ones are kept, in order"
	);
}

#[test]
fn a_target_named_twice_is_forwarded_once() {
	let outcome = run(
		"redirect \"Who@target.example\"; redirect \"who@TARGET.example\"; \
		 redirect \"other@target.example\";",
	);
	assert_eq!(
		outcome.redirects,
		vec!["Who@target.example", "other@target.example"]
	);
}

#[test]
fn a_redirect_over_the_limit_still_cancels_the_implicit_keep() {
	let script: String = (0..=MAX_REDIRECTS)
		.map(|n| format!("redirect \"u{n}@target.example\";"))
		.collect();
	let outcome = run(&script);
	assert!(
		!outcome.keep,
		"the message was redirected, so it is not kept"
	);
}
