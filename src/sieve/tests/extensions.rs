//! The extension list is what the interpreter does, in both directions: a
//! script may `require` everything it can run, and the list names nothing it
//! cannot.

use super::super::extensions;
use super::super::interp::{Message, Outcome, evaluate};
use super::super::parser::parse;
use super::compare::COMPARATORS;
use super::lexer::tokenize;

const MSG: &[u8] =
	b"From: Ken+sieve@Example.org\r\nTo: bob@example.net\r\nSubject: Hello 42\r\nX-N: 42\r\n\r\nthe body\r\n";

fn run(script: &str) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(
		&commands,
		&Message::parse(MSG).with_envelope(
			"s@x.example".to_string(),
			vec!["bob@example.net".to_string()],
		),
	)
}

/// For every extension a script that uses it and what that must do.
#[test]
fn every_listed_extension_is_one_the_interpreter_runs() {
	type Check = fn(&Outcome) -> bool;
	let table: [(&str, &str, Check); 15] = [
		("fileinto", "fileinto \"Work\";", |o| o.fileinto == ["Work"]),
		(
			"envelope",
			"if envelope :is \"from\" \"s@x.example\" { discard; }",
			|o| o.discarded,
		),
		("vacation", "vacation \"away\";", |o| o.vacation.is_some()),
		("imap4flags", "addflag \"\\\\Flagged\";", |o| {
			o.flags == ["\\Flagged"]
		}),
		(
			"relational",
			"if header :value \"gt\" :comparator \"i;ascii-numeric\" \"x-n\" \"5\" { discard; }",
			|o| o.discarded,
		),
		("variables", "set \"f\" \"Work\"; fileinto \"${f}\";", |o| {
			o.fileinto == ["Work"]
		}),
		("reject", "reject \"no\";", |o| {
			o.reject.as_deref() == Some("no")
		}),
		("ereject", "ereject \"no\";", |o| {
			o.reject.as_deref() == Some("no")
		}),
		("copy", "fileinto :copy \"Work\";", |o| o.keep),
		("body", "if body :contains \"body\" { discard; }", |o| {
			o.discarded
		}),
		(
			"date",
			"if date :is \"date\" \"year\" \"1999\" { discard; }",
			|o| !o.discarded,
		),
		("mailbox", "fileinto :create \"New\";", |o| {
			o.fileinto_creates.contains("New")
		}),
		(
			"comparator-i;ascii-numeric",
			"if header :value \"ge\" :comparator \"i;ascii-numeric\" \"x-n\" \"42\" { discard; }",
			|o| o.discarded,
		),
		(
			"comparator-i;octet",
			"if header :is :comparator \"i;octet\" \"subject\" \"hello 42\" { discard; }",
			|o| !o.discarded,
		),
		(
			"comparator-i;ascii-casemap",
			"if header :is :comparator \"i;ascii-casemap\" \"subject\" \"hello 42\" { discard; }",
			|o| o.discarded,
		),
	];
	for (extension, script, expected) in table {
		assert!(
			extensions().any(|e| e == extension),
			"{extension} is implemented but not listed"
		);
		let outcome = run(&format!("require \"{extension}\";\n{script}"));
		assert!(expected(&outcome), "{extension}: {outcome:?}");
	}
	// subaddress needs no `require` of its own check above: :user and :detail.
	assert!(extensions().any(|e| e == "subaddress"));
	assert!(
		run("require \"subaddress\"; if address :detail :is \"from\" \"sieve\" { discard; }")
			.discarded
	);
	assert!(
		run("require \"subaddress\"; if address :user :is \"from\" \"ken\" { discard; }").discarded
	);
	// Nothing is listed that is not in the table or the subaddress checks.
	let known: Vec<&str> = table
		.iter()
		.map(|row| row.0)
		.chain(["subaddress"])
		.collect();
	for extension in extensions() {
		assert!(
			known.contains(&extension),
			"{extension} is listed but has no check here"
		);
	}
}

#[test]
fn the_comparators_listed_are_the_ones_implemented() {
	for comparator in COMPARATORS {
		let name = format!("comparator-{comparator}");
		assert!(extensions().any(|e| e == name), "{name}");
	}
	for extension in extensions().filter_map(|e| e.strip_prefix("comparator-")) {
		assert!(COMPARATORS.contains(&extension), "{extension}");
	}
}
