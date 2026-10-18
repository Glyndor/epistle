//! A sender can put as many headers in a message as the message may hold.
//! Looking them up, and visiting what a lookup finds, is work a run pays
//! for, and does not cost a pass over every header each time.

use std::time::{Duration, Instant};

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

/// A message with `count` headers named `x` (and a Subject).
fn crowded(count: usize) -> Vec<u8> {
	let mut raw = b"Subject: hi\r\n".to_vec();
	for _ in 0..count {
		raw.extend_from_slice(b"x: y\r\n");
	}
	raw.extend_from_slice(b"\r\nbody\r\n");
	raw
}

fn run(script: &str, raw: &[u8]) -> (Outcome, Duration) {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	let message = Message::parse(raw);
	let started = Instant::now();
	let outcome = evaluate(&commands, &message);
	(outcome, started.elapsed())
}

#[test]
fn looking_up_a_header_that_is_not_there_does_not_read_every_header() {
	// 3000 tests over 300 000 headers: nine hundred million header
	// comparisons if each test reads them all.
	let script = "if exists \"x-nothere\" { discard; }\n".repeat(3000);
	let (outcome, took) = run(&script, &crowded(300_000));
	assert!(!outcome.aborted && !outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn a_long_list_of_names_is_a_lookup_each() {
	// One test (one step) with 60 000 names over 200 000 headers.
	let names: Vec<String> = (0..60_000).map(|n| format!("\"x-{n:05}\"")).collect();
	let script = format!(
		"if header :contains [{}] \"zzz\" {{ discard; }}\n",
		names.join(",")
	);
	let (outcome, took) = run(&script, &crowded(200_000));
	assert!(!outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn visiting_the_values_of_a_header_is_paid_for() {
	// A million values of `x`. A lookup visits the first thousand of them, and
	// a test that does so again and again stops the run when it has spent what
	// it may.
	let script = "if header :contains \"x\" \"zzz\" { discard; }\n".repeat(5000);
	let (outcome, took) = run(&script, &crowded(1_000_000));
	assert!(outcome.aborted, "the run was not stopped");
	assert!(took < Duration::from_secs(20), "{took:?}");
}

#[test]
fn counting_headers_is_a_lookup_not_a_pass() {
	let script = "require \"relational\";\nif header :count \"ge\" :comparator \"i;ascii-numeric\" \"x\" \"1000000\" { discard; }\n".repeat(3000);
	let (outcome, took) = run(&script, &crowded(300_000));
	assert!(!outcome.aborted && !outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn the_headers_are_still_found_whatever_their_case() {
	let raw = b"X-Foo: one\r\nx-foo: two\r\nSubject: s\r\n\r\nb\r\n";
	let (outcome, _) = run("if header :is \"X-FOO\" \"two\" { discard; }", raw);
	assert!(outcome.discarded);
	let (outcome, _) = run(
		"require \"relational\";\nif header :count \"eq\" :comparator \"i;ascii-numeric\" \"x-foo\" \"2\" { discard; }",
		raw,
	);
	assert!(outcome.discarded);
}

#[test]
fn a_name_visits_its_first_thousand_values() {
	let mut raw = Vec::new();
	for n in 0..3000 {
		let value = if n == 2500 { "needle" } else { "y" };
		raw.extend_from_slice(format!("x: {value}\r\n").as_bytes());
	}
	raw.extend_from_slice(b"\r\nb\r\n");
	let script = "if header :contains \"x\" \"needle\" { discard; }";
	assert!(
		!run(script, &raw).0.discarded,
		"the 2501st value is past the quota"
	);
	let mut early = raw.clone();
	early.splice(0..0, b"x: needle\r\n".iter().copied());
	assert!(
		run(script, &early).0.discarded,
		"the first thousand are read"
	);
	// A value is read up to 64 KiB.
	let long = format!("Subject: {}needle\r\n\r\nb\r\n", "y".repeat(70_000));
	assert!(
		!run(
			"if header :contains \"subject\" \"needle\" { discard; }",
			long.as_bytes()
		)
		.0
		.discarded
	);
	let near = format!("Subject: {}needle\r\n\r\nb\r\n", "y".repeat(60_000));
	assert!(
		run(
			"if header :contains \"subject\" \"needle\" { discard; }",
			near.as_bytes()
		)
		.0
		.discarded
	);
}

#[test]
fn only_the_first_ten_thousand_headers_are_read_and_a_lookup_says_so() {
	// Subject plus 20 000 `x`: the interpreter reads the first 10 000 of all.
	let raw = crowded(20_000);
	let (outcome, _) = run(
		"require \"relational\";\nif header :count \"ge\" :comparator \"i;ascii-numeric\" \"x\" \"10000\" { discard; }\n",
		&raw,
	);
	assert!(!outcome.discarded, "9 999 `x` were read: {outcome:?}");
	assert!(outcome.inspection_truncated);
	let (outcome, _) = run(
		"if header :contains \"subject\" \"hi\" { discard; }\n",
		&raw,
	);
	assert!(
		outcome.discarded,
		"the headers before the cut are all there"
	);
	let (outcome, _) = run("if exists \"subject\" { discard; }\n", &crowded(10));
	assert!(outcome.discarded && !outcome.inspection_truncated);
}
