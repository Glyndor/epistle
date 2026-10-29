//! What a filter sees of a message too big to look at whole: the same window
//! for every test, a visible mark when a test hit it, and a run that stays
//! well inside its allowance for a script of ordinary rules.

use super::super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::super::parser::parse;

const MIB: usize = 1 << 20;

fn run(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(raw))
}

#[test]
fn a_name_reads_its_first_64_kib_and_no_more() {
	// 100 values of 1 KiB: the first 64 fill the quota, the needle is the 80th.
	let mut raw = Vec::new();
	for n in 0..100 {
		let value = if n == 80 {
			"needle".to_string()
		} else {
			"y".repeat(1000)
		};
		raw.extend_from_slice(format!("x: {value}\r\n").as_bytes());
	}
	raw.extend_from_slice(b"\r\nb\r\n");
	let outcome = run("if header :contains \"x\" \"needle\" { discard; }", &raw);
	assert!(!outcome.discarded, "past the quota of the name");
	assert!(
		outcome.inspection_truncated,
		"and the test says it did not see everything"
	);
}

#[test]
fn a_huge_header_does_not_hide_the_others_listed_with_it() {
	let raw = format!(
		"X-Big: {}\r\nSubject: win the needle\r\n\r\nb\r\n",
		"y".repeat(5 * MIB)
	);
	let script = "if header :contains [\"x-big\", \"subject\"] \"needle\" { discard; }";
	let outcome = run(script, raw.as_bytes());
	assert!(outcome.discarded, "{outcome:?}");
	assert!(
		outcome.inspection_truncated,
		"the big one was cut, and that is noted"
	);
}

#[test]
fn a_thousand_received_do_not_hide_from() {
	let mut raw = "Received: from a by b\r\n".repeat(5000);
	raw.push_str("From: spammer@elsewhere.example\r\n\r\nb\r\n");
	let script =
		"if address :is [\"received\", \"from\"] \"spammer@elsewhere.example\" { discard; }";
	assert!(run(script, raw.as_bytes()).discarded);
	let script = "if header :contains [\"received\", \"from\"] \"spammer\" { discard; }";
	assert!(run(script, raw.as_bytes()).discarded);
}

#[test]
fn only_so_many_names_are_read_by_one_lookup() {
	let names: Vec<String> = (0..20).map(|n| format!("\"x{n}\"")).collect();
	let script = format!(
		"if header :contains [{}] \"needle\" {{ discard; }}",
		names.join(",")
	);
	let in_the_sixteenth = run(&script, b"x15: needle\r\n\r\nb\r\n");
	assert!(in_the_sixteenth.discarded && !in_the_sixteenth.inspection_truncated);
	let in_the_seventeenth = run(&script, b"x16: needle\r\n\r\nb\r\n");
	assert!(!in_the_seventeenth.discarded && in_the_seventeenth.inspection_truncated);
}

#[test]
fn a_count_is_of_every_header_and_does_not_count_as_truncation() {
	let raw = "x: y\r\n".repeat(5000) + "\r\nb\r\n";
	let script = "require \"relational\";\nif header :count \"eq\" :comparator \"i;ascii-numeric\" \"x\" \"5000\" { discard; }";
	let outcome = run(script, raw.as_bytes());
	assert!(outcome.discarded, "{outcome:?}");
	assert!(!outcome.inspection_truncated);
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
