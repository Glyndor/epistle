//! `:matches` runs on text and patterns a user and a sender choose, so its
//! cost and its stack have to be bounded whatever they contain.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use super::*;

fn matches_spec() -> MatchSpec {
	match_spec(&[Argument::Tag("matches".to_string())])
}

/// `spec.test(text, pattern)` on a thread of its own with a stack far bigger
/// than any sane recursion needs, giving up after five seconds. A matcher
/// that recurses per wildcard or tries every split is seen failing an
/// assertion here instead of aborting the test process.
fn run(pattern: String, text: String) -> Option<(bool, HashMap<String, String>)> {
	let (sender, receiver) = mpsc::channel();
	std::thread::Builder::new()
		.stack_size(1 << 30)
		.spawn(move || {
			let mut vars = HashMap::new();
			let matched = matches_spec().test(&text, &pattern, &mut vars);
			let _ = sender.send((matched, vars));
		})
		.expect("spawn");
	receiver.recv_timeout(Duration::from_secs(5)).ok()
}

#[test]
fn a_pattern_of_a_hundred_thousand_wildcards_is_answered_at_once() {
	let pattern = format!("{}b", "*".repeat(100_000));
	let answer = run(pattern, "aaaa".to_string());
	assert_eq!(
		answer.map(|(matched, _)| matched),
		Some(false),
		"no answer within five seconds"
	);
}

#[test]
fn a_pattern_that_made_the_search_exponential_is_answered_at_once() {
	// Twenty `*a` followed by a letter that is not there: every way of
	// splitting forty `a`s among twenty stars was tried.
	let pattern = format!("{}b", "*a".repeat(20));
	let answer = run(pattern, "a".repeat(40));
	assert_eq!(
		answer.map(|(matched, _)| matched),
		Some(false),
		"no answer within five seconds"
	);
}

#[test]
fn a_pattern_over_the_wildcard_limit_matches_nothing() {
	let at_limit = "*".repeat(MAX_WILDCARDS);
	assert_eq!(run(at_limit, "abc".to_string()).map(|a| a.0), Some(true));
	let over = "*".repeat(MAX_WILDCARDS + 1);
	assert_eq!(run(over, "abc".to_string()).map(|a| a.0), Some(false));
	let long = "a".repeat(MAX_PATTERN_CHARS + 1);
	assert_eq!(run(long.clone(), long).map(|a| a.0), Some(false));
	let longest = "a".repeat(MAX_PATTERN_CHARS);
	assert_eq!(run(longest.clone(), longest).map(|a| a.0), Some(true));
}

#[test]
fn text_over_the_length_limit_matches_nothing() {
	let at_limit = "a".repeat(MAX_TEXT_CHARS);
	assert_eq!(run("*".to_string(), at_limit).map(|a| a.0), Some(true));
	let over = "a".repeat(MAX_TEXT_CHARS + 1);
	assert_eq!(run("*".to_string(), over).map(|a| a.0), Some(false));
}

#[test]
fn a_refused_match_sets_no_variables() {
	let over = "*".repeat(MAX_WILDCARDS + 1);
	let (matched, vars) = run(over, "abc".to_string()).expect("answered");
	assert!(!matched);
	assert!(vars.is_empty());
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
	for (pattern, text, expected) in table {
		let (matched, vars) = run(pattern.to_string(), text.to_string()).expect("answered");
		assert!(matched, "{pattern} on {text}");
		let got: Vec<&str> = (1..=expected.len())
			.map(|i| vars[&i.to_string()].as_str())
			.collect();
		assert_eq!(got, expected, "{pattern} on {text}");
		assert_eq!(vars["0"], text);
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
	] {
		let with = spec.test(text, pattern, &mut HashMap::new());
		assert_eq!(spec.test_simple(text, pattern), with, "{pattern} on {text}");
	}
}
