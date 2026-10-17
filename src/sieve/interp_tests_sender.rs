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

/// The same, with `head` at the start of the body (inside the window the
/// `body` test reads).
fn big_with_head(mib: usize, head: &str) -> Vec<u8> {
	let mut raw = b"From: ext@elsewhere.example\r\nSubject: hi\r\n\r\n".to_vec();
	raw.extend_from_slice(head.as_bytes());
	raw.extend(std::iter::repeat_n(b'x', mib * MIB));
	raw
}

const TEN_KEYS: &str = "require [\"body\"];\n\
	if body :contains [\"k1\",\"k2\",\"k3\",\"k4\",\"k5\",\"k6\",\"k7\",\"k8\",\"k9\",\"spamword\"] { discard; stop; }\n";

#[test]
fn a_big_message_does_not_get_past_a_body_discard() {
	// Ten keys over a 6 MiB body used to cost more than a run may, the run was
	// abandoned and the message kept.
	for mib in [1, 6] {
		let outcome = run(TEN_KEYS, &big_with_head(mib, "spamword "));
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
fn a_run_that_runs_out_keeps_where_the_message_goes_and_drops_what_would_send() {
	let message = b"Subject: hi\r\n\r\nx\r\n";
	let filler = "noop;\n".repeat(25_000);
	// A `discard` decided before stays decided; the `redirect` is dropped, and
	// so is what comes after the stop.
	let outcome = run(
		&format!("discard;\nredirect \"a@target.example\";\n{filler}fileinto \"Z\";\n"),
		message,
	);
	assert!(outcome.aborted);
	assert!(outcome.discarded && !outcome.keep, "{outcome:?}");
	assert!(
		outcome.redirects.is_empty() && outcome.fileinto.is_empty(),
		"{outcome:?}"
	);
	assert_eq!(outcome.dropped.redirects, 1);
	// A `fileinto` decided before stays decided.
	let outcome = run(&format!("fileinto \"A\";\n{filler}"), message);
	assert_eq!(outcome.fileinto, vec!["A".to_string()]);
	assert!(outcome.aborted && !outcome.keep);
	// Nothing decided about where it goes, only a `redirect`: the redirect is
	// dropped and the message is kept, not lost behind a redirect that never
	// went out.
	let outcome = run(
		&format!("redirect \"a@target.example\";\n{filler}"),
		message,
	);
	assert!(outcome.redirects.is_empty() && outcome.keep, "{outcome:?}");
	// `reject` and `vacation` are dropped too.
	let outcome = run(
		&format!(
			"require [\"reject\", \"vacation\"];\nvacation \"away\";\nreject \"no\";\n{filler}"
		),
		message,
	);
	assert!(
		outcome.reject.is_none() && outcome.vacation.is_none() && outcome.keep,
		"{outcome:?}"
	);
	assert!(outcome.dropped.reject && outcome.dropped.vacation);
}

#[test]
fn a_run_inside_its_allowance_sends_what_it_asked_to() {
	let outcome = run(
		"redirect \"a@target.example\";\n",
		b"Subject: hi\r\n\r\nx\r\n",
	);
	assert_eq!(outcome.redirects, vec!["a@target.example".to_string()]);
	assert!(!outcome.aborted && !outcome.keep);
}

#[test]
fn a_big_message_neither_loses_a_discard_nor_fires_a_later_redirect() {
	let script = "require [\"body\"];\ndiscard;\nif body :contains \"nothere\" { stop; }\nredirect \"a@target.example\";\n";
	let outcome = run(script, &big(24, ""));
	assert!(outcome.discarded && !outcome.aborted, "{outcome:?}");
	assert_eq!(
		outcome.redirects,
		vec!["a@target.example".to_string()],
		"no budget was spent beyond the allowance"
	);
}

#[test]
fn a_script_that_reads_the_body_too_many_times_runs_out_whatever_the_size() {
	// The body test reads a fixed window of 1 MiB. 300 passes over it are 300
	// MiB of reading, more than a run may: for a 2 MiB message and for a 24 MiB
	// one alike. The sender cannot move the line by choosing the size.
	let rule = "if body :contains \"nothere\" { discard; }\n";
	let script = format!("require [\"body\"];\n{}", rule.repeat(300));
	for mib in [2, 24] {
		assert!(run(&script, &big(mib, "")).aborted, "{mib} MiB");
	}
	assert!(!run(&script, &big(0, "")).aborted, "a message of nothing");
}

#[test]
fn only_the_first_mebibyte_of_the_body_is_read() {
	let script = "require [\"body\"];\nif body :contains \"spamword\" { discard; }\n";
	assert!(run(script, &big(0, "spamword")).discarded);
	assert!(
		!run(script, &big(2, "spamword")).discarded,
		"past the window"
	);
}
