//! What one run of a script can make the server spend: memory for the
//! strings it builds, steps, and matching work.

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

fn run_with(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(&commands, &Message::parse(raw))
}

fn run(script: &str) -> Outcome {
	run_with(script, b"Subject: hi\r\n\r\nx\r\n")
}

#[test]
fn doubling_a_variable_cannot_build_a_huge_string() {
	// 610 octets of script doubled a variable on every line until the
	// process held two gigabytes. Twenty doublings are ten mebibytes
	// without a limit, and the limit is 4096 octets.
	let mut script =
		String::from("require [\"variables\", \"reject\"];\nset \"a\" \"0123456789\";\n");
	for _ in 0..20 {
		script.push_str("set \"a\" \"${a}${a}\";\n");
	}
	script.push_str("reject \"${a}\";\n");
	let outcome = run(&script);
	assert_eq!(outcome.reject.as_deref().map(str::len), Some(4096));
	assert!(!outcome.aborted);
}

#[test]
fn a_string_built_from_many_references_stays_near_the_script_text() {
	let mut script = String::from("require [\"variables\", \"reject\"];\nset \"a\" \"");
	script.push_str(&"y".repeat(4096));
	script.push_str("\";\nreject \"");
	script.push_str(&"${a}".repeat(2000));
	script.push_str("\";\n");
	let outcome = run(&script);
	let reject = outcome.reject.expect("rejected");
	assert_eq!(
		reject.len(),
		8000,
		"no more than the octets of the template"
	);
	assert!(reject.starts_with('y'));
}

#[test]
fn a_run_with_too_many_steps_is_abandoned_and_the_message_kept() {
	let script = format!("discard;\n{}fileinto \"Z\";\n", "keep;\n".repeat(25_000));
	let outcome = run(&script);
	assert!(outcome.aborted, "a run over 20000 steps is abandoned");
	assert!(outcome.keep && !outcome.discarded);
	assert!(outcome.fileinto.is_empty() && outcome.redirects.is_empty());
}

#[test]
fn a_run_inside_its_steps_is_not_abandoned() {
	let script = format!("{}fileinto \"Z\";\n", "keep;\n".repeat(19_000));
	let outcome = run(&script);
	assert!(!outcome.aborted);
	assert_eq!(outcome.fileinto, vec!["Z".to_string()]);
}

#[test]
fn matching_work_is_budgeted_across_the_run() {
	// Each of these tests tries a 200-character segment at every position of
	// an 8000-character subject: about 1.6 million comparisons. Forty of
	// them are past the budget of a run.
	let key = format!("*{}b*", "a".repeat(200));
	let test = format!("if header :matches \"subject\" \"{key}\" {{ discard; }}\n");
	let raw = format!("Subject: {}\r\n\r\nx\r\n", "a".repeat(8000));
	let outcome = run_with(&test.repeat(40), raw.as_bytes());
	assert!(
		outcome.aborted,
		"forty large matches are more than a run may ask for"
	);
	assert!(outcome.keep && !outcome.discarded);
	let outcome = run_with(&test.repeat(5), raw.as_bytes());
	assert!(!outcome.aborted);
}

#[test]
fn an_abandoned_run_drops_what_it_had_asked_for() {
	let script = format!(
		"redirect \"a@target.example\";\nfileinto \"X\";\n{}",
		"keep;\n".repeat(25_000)
	);
	let outcome = run(&script);
	assert!(outcome.aborted);
	assert!(outcome.redirects.is_empty() && outcome.fileinto.is_empty());
	assert!(outcome.keep);
}
