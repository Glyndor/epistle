//! A sender chooses how big a message is and what is in it. Whether a
//! filter's rules run must not depend on that: a big message must not be the
//! way past a user's `discard`.

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

const MIB: usize = 1 << 20;

fn run(script: &str, raw: &[u8]) -> Outcome {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	evaluate(
		&commands,
		&Message::parse(raw).with_envelope(
			"ext@elsewhere.example".to_string(),
			vec!["me@example.org".to_string()],
		),
	)
}

/// A message of `mib` mebibytes whose body ends with `tail`.
fn big(mib: usize, tail: &str) -> Vec<u8> {
	let mut raw = b"From: ext@elsewhere.example\r\nSubject: hi\r\n\r\n".to_vec();
	raw.extend(std::iter::repeat_n(b'x', mib * MIB));
	raw.extend_from_slice(tail.as_bytes());
	raw
}

const TEN_KEYS: &str = "require [\"body\"];\n\
	if body :contains [\"k1\",\"k2\",\"k3\",\"k4\",\"k5\",\"k6\",\"k7\",\"k8\",\"k9\",\"spamword\"] { discard; stop; }\n";

#[test]
fn a_big_message_does_not_get_past_a_body_discard() {
	// Ten keys over a 6 MiB body used to cost more than a run may, the run was
	// abandoned and the message kept.
	for mib in [1, 6] {
		let outcome = run(TEN_KEYS, &big(mib, " spamword"));
		assert!(outcome.discarded, "{mib} MiB: {outcome:?}");
		assert!(!outcome.aborted, "{mib} MiB");
	}
}

#[test]
fn a_big_body_does_not_cost_the_discard_that_comes_after() {
	let script = "require [\"body\", \"fileinto\"];\n\
		if body :matches \"*unsubscribe*\" { fileinto \"News\"; stop; }\n\
		if address :is \"from\" \"ext@elsewhere.example\" { discard; stop; }\n";
	for mib in [1, 12] {
		let outcome = run(script, &big(mib, ""));
		assert!(outcome.discarded, "{mib} MiB: {outcome:?}");
		assert!(!outcome.aborted, "{mib} MiB");
	}
}

#[test]
fn several_body_rules_still_run_on_a_big_message() {
	let rule = "if body :contains [\"a1\", \"a2\", \"a3\"] { fileinto \"A\"; stop; }\n";
	let script = format!(
		"require [\"body\", \"fileinto\"];\n{}discard;\n",
		rule.repeat(4)
	);
	let outcome = run(&script, &big(8, ""));
	assert!(outcome.discarded && !outcome.aborted, "{outcome:?}");
}

#[test]
fn a_run_that_runs_out_stops_where_it_is_and_keeps_what_it_decided() {
	// Not "throw everything away": a `discard` already decided stays decided.
	let script = format!("discard;\n{}fileinto \"Z\";\n", "noop;\n".repeat(25_000));
	let outcome = run(&script, b"Subject: hi\r\n\r\nx\r\n");
	assert!(outcome.aborted);
	assert!(outcome.discarded && !outcome.keep, "{outcome:?}");
	assert!(
		outcome.fileinto.is_empty(),
		"the rule after the stop did not run"
	);
	let script = format!(
		"fileinto \"A\";\nredirect \"a@target.example\";\n{}",
		"noop;\n".repeat(25_000)
	);
	let outcome = run(&script, b"Subject: hi\r\n\r\nx\r\n");
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
	assert_eq!(outcome.redirects, vec!["a@target.example".to_string()]);
}

#[test]
fn a_script_that_scans_the_body_too_many_times_runs_out_whatever_the_size() {
	// Past the allowance, and the same for a small and a large message: the
	// sender does not decide it. 100 passes over the body cost 100 times its
	// size; a run may afford 64 times it plus a fixed amount.
	let rule = "if body :contains \"nothere\" { discard; }\n";
	let script = format!("require [\"body\"];\n{}", rule.repeat(100));
	let outcome = run(&script, &big(4, ""));
	assert!(outcome.aborted, "100 passes over 4 MiB");
	let outcome = run(&script, &big(0, ""));
	assert!(!outcome.aborted, "100 passes over nothing");
}
