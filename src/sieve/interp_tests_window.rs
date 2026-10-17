//! What a filter sees of a message too big to look at whole: the same window
//! for every test, a visible mark when a test hit it, and a run that stays
//! well inside its allowance for a script of ordinary rules.

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

const MIB: usize = 1 << 20;

fn run(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(raw))
}

#[test]
fn a_lookup_reads_a_megabyte_of_values_in_all() {
	// 100 values of 60 KiB: the first 17 or so fill the megabyte, and the
	// needle is in the 50th.
	let mut raw = Vec::new();
	for n in 0..100 {
		let value = if n == 50 {
			format!("{}needle", "y".repeat(60_000))
		} else {
			"y".repeat(60_000)
		};
		raw.extend_from_slice(format!("x: {value}\r\n").as_bytes());
	}
	raw.extend_from_slice(b"\r\nb\r\n");
	let outcome = run("if header :contains \"x\" \"needle\" { discard; }", &raw);
	assert!(!outcome.discarded, "the 51st value is past the megabyte");
	assert!(
		outcome.inspection_truncated,
		"and the test says it did not see everything"
	);
}

#[test]
fn a_count_sees_the_same_window_as_the_values() {
	let raw = "x: y\r\n".repeat(3000) + "\r\nb\r\n";
	let script = "require \"relational\";\nif header :count \"eq\" :comparator \"i;ascii-numeric\" \"x\" \"1000\" { discard; }";
	let outcome = run(script, raw.as_bytes());
	assert!(
		outcome.discarded,
		"the count is of the values a test can see"
	);
	assert!(outcome.inspection_truncated);
}

#[test]
fn an_inspection_that_reached_nothing_is_not_marked() {
	let outcome = run(
		"require \"body\";\nif anyof(header :contains \"subject\" \"a\", body :contains \"b\", exists \"x\") { discard; }",
		b"Subject: hi\r\nx: 1\r\n\r\nbody\r\n",
	);
	assert!(!outcome.inspection_truncated);
	let outcome = run(
		"require \"body\";\nif body :contains \"zzz\" { discard; }",
		&[
			b"Subject: s\r\n\r\n".as_slice(),
			"x".repeat(MIB + 1).as_bytes(),
		]
		.concat(),
	);
	assert!(outcome.inspection_truncated, "a body past the window");
}

#[test]
fn two_hundred_ordinary_rules_never_run_out_on_a_huge_message() {
	// 200 rules a person would write, against 25 MiB: a body of 24 MiB and
	// 100 000 Received headers. The run reads at most what its windows allow.
	let mut script = String::from("require [\"body\", \"fileinto\", \"relational\"];\n");
	for n in 0..80 {
		script.push_str(&format!(
			"if header :contains \"subject\" [\"alpha{n}\", \"beta{n}\"] {{ fileinto \"F{n}\"; stop; }}\n"
		));
	}
	for n in 0..40 {
		script.push_str(&format!(
			"if address :is \"from\" \"nobody{n}@example.net\" {{ fileinto \"G{n}\"; stop; }}\n"
		));
	}
	for n in 0..40 {
		script.push_str(&format!(
			"if exists \"x-list-{n}\" {{ fileinto \"H{n}\"; stop; }}\n"
		));
	}
	for n in 0..20 {
		script.push_str(&format!(
			"if body :contains [\"one{n}\", \"two{n}\", \"three{n}\"] {{ fileinto \"B{n}\"; stop; }}\n"
		));
	}
	for n in 0..20 {
		script.push_str(&format!(
			"if header :matches \"received\" \"*zzz{n}*\" {{ fileinto \"R{n}\"; stop; }}\n"
		));
	}
	script.push_str("discard;\n");
	let mut raw = b"From: ext@elsewhere.example\r\nSubject: hi\r\n".to_vec();
	raw.extend_from_slice("Received: from a by b\r\n".repeat(100_000).as_bytes());
	raw.extend_from_slice(b"\r\n");
	raw.extend(std::iter::repeat_n(b'x', 24 * MIB));
	let outcome = run(&script, &raw);
	assert!(!outcome.aborted, "{outcome:?}");
	assert!(
		outcome.discarded,
		"every rule ran, and the last one decided"
	);
}
