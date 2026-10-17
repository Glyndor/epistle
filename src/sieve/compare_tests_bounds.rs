//! `:matches` runs on text and patterns a user and a sender choose, so its
//! cost and its stack have to be bounded whatever they contain, and a text
//! the sender made long must never turn into "does not match".

use std::sync::mpsc;
use std::time::Duration;

use super::*;

fn matches_spec() -> MatchSpec {
	match_spec(&[Argument::Tag("matches".to_string())])
}

/// What one `:matches` test came to: whether it matched, and the run it was
/// part of.
struct Answer {
	matched: bool,
	env: Env,
}

/// `spec.test(text, pattern)` on a thread of its own with a very large
/// stack, giving up after ten seconds. A matcher that recurses per wildcard
/// or tries every split is seen failing an assertion here instead of
/// aborting the test process.
fn run(pattern: String, text: String) -> Option<Answer> {
	let (sender, receiver) = mpsc::channel();
	std::thread::Builder::new()
		.stack_size(1 << 30)
		.spawn(move || {
			let mut env = Env::default();
			let matched = matches_spec().test(&text, &pattern, &mut env);
			let _ = sender.send(Answer { matched, env });
		})
		.expect("spawn");
	receiver.recv_timeout(Duration::from_secs(10)).ok()
}

fn matched(pattern: &str, text: &str) -> bool {
	run(pattern.to_string(), text.to_string())
		.expect("answered in time")
		.matched
}

#[test]
fn a_pattern_of_a_hundred_thousand_wildcards_is_refused_at_once() {
	let pattern = format!("{}b", "*".repeat(100_000));
	let answer = run(pattern, "aaaa".to_string()).expect("no answer within ten seconds");
	assert!(!answer.matched);
	assert!(
		answer.env.exhausted(),
		"the run is abandoned, not told 'no match'"
	);
}

#[test]
fn a_pattern_that_made_the_search_exponential_is_answered_at_once() {
	// Twenty `*a` followed by a letter that is not there: every way of
	// splitting forty `a`s among twenty stars was tried.
	let pattern = format!("{}b", "*a".repeat(20));
	let answer = run(pattern, "a".repeat(40)).expect("no answer within ten seconds");
	assert!(!answer.matched);
	assert!(!answer.env.exhausted(), "a plain mismatch is a mismatch");
}

#[test]
fn a_pattern_over_the_limits_is_refused_not_unmatched() {
	assert!(matched(&"*".repeat(MAX_WILDCARDS), "abc"));
	let over = run("*".repeat(MAX_WILDCARDS + 1), "abc".to_string()).expect("answered");
	assert!(!over.matched && over.env.exhausted());
	let long = "a".repeat(MAX_PATTERN_CHARS + 1);
	let refused = run(long.clone(), long).expect("answered");
	assert!(!refused.matched && refused.env.exhausted());
	let longest = "a".repeat(MAX_PATTERN_CHARS);
	assert!(matched(&longest, &longest));
}

#[test]
fn a_refused_match_sets_no_variables() {
	let answer = run("*".repeat(MAX_WILDCARDS + 1), "abc".to_string()).expect("answered");
	assert!(answer.env.get("0").is_none() && answer.env.get("1").is_none());
}

#[test]
fn a_long_text_still_matches() {
	// A sender can make a Subject as long as the message allows. It must
	// not stop a filter from seeing what is in it.
	let mut text = "a".repeat(2_000_000);
	text.push_str("foo");
	text.push_str(&"b".repeat(2_000_000));
	assert!(matched("*foo*", &text));
	assert!(!matched("*fob*", &text));
	assert!(matched("a*foo*b", &text));
	assert!(matched("*", &text));
	assert!(!matched("?", &text));
}

#[test]
fn work_that_runs_past_the_budget_abandons_the_run() {
	// Every position of two million characters tried against a hundred:
	// two hundred million comparisons, past what a run may spend.
	let pattern = format!("*{}b*", "a".repeat(100));
	let answer = run(pattern, "a".repeat(2_000_000)).expect("answered");
	assert!(!answer.matched);
	assert!(answer.env.exhausted());
}

#[test]
fn captures_keep_the_leftmost_shortest_assignment() {
	let table = [
		("a*c", "abcbc", vec!["bcb"]),
		("*b*", "abbb", vec!["a", "bb"]),
		("*@*", "bob@example.net", vec!["bob", "example.net"]),
		("a?c", "abc", vec!["b"]),
		("**", "xy", vec!["", "xy"]),
		("*?*", "abc", vec!["", "a", "bc"]),
		("x*", "x", vec![""]),
	];
	for (pattern, text, expected) in &table {
		let answer = run((*pattern).to_string(), (*text).to_string()).expect("answered");
		assert!(answer.matched, "{pattern} on {text}");
		let got: Vec<&str> = (1..=expected.len())
			.map(|i| answer.env.get(&i.to_string()).expect("capture"))
			.collect();
		assert_eq!(&got, expected, "{pattern} on {text}");
		assert_eq!(answer.env.get("0"), Some(*text));
	}
}

#[test]
fn matching_without_captures_agrees_with_matching_with_them() {
	let spec = matches_spec();
	for (pattern, text) in [
		("a*c", "abcbc"),
		("a*c", "abcbd"),
		("*", ""),
		("?", ""),
		("A*B", "axxb"),
		("*a*a*a*", "aaa"),
		("*a*a*a*", "aa"),
		("ab*ab", "ab"),
		("ab*ab", "abab"),
		("*ab*ab*", "xabxabx"),
		("a?*?b", "aXb"),
		("a?*?b", "aXYb"),
	] {
		let with = spec.test(text, pattern, &mut Env::default());
		assert_eq!(spec.test_simple(text, pattern), with, "{pattern} on {text}");
	}
}

#[test]
fn the_search_stops_as_soon_as_the_budget_is_spent() {
	let text: String = "a".repeat(2_000_000);
	let pattern = format!("*{}b*", "a".repeat(100));
	let mut steps = 0;
	let outcome = glob(&pattern, &text, &mut steps, 1000);
	assert!(matches!(outcome, Glob::Refused));
	assert!(
		steps <= 1000 + MAX_PATTERN_CHARS as u64,
		"{steps} comparisons for a budget of 1000"
	);
}
