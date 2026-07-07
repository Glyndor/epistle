//! Tests for Sieve match types, comparators and positional-argument parsing.

use super::*;
use std::collections::HashMap;

fn tag(name: &str) -> Argument {
	Argument::Tag(name.to_string())
}
fn str_arg(value: &str) -> Argument {
	Argument::Str(value.to_string())
}

#[test]
fn default_match_is_case_insensitive_is() {
	let spec = match_spec(&[]);
	assert!(spec.test_simple("Hello", "hello"));
	assert!(!spec.test_simple("Hello", "help"));
}

#[test]
fn octet_comparator_is_case_sensitive() {
	let args = [tag("comparator"), str_arg("i;octet")];
	let spec = match_spec(&args);
	assert!(spec.test_simple("Hello", "Hello"));
	assert!(!spec.test_simple("Hello", "hello"));
}

#[test]
fn value_relational_numeric() {
	let args = [
		tag("value"),
		str_arg("ge"),
		tag("comparator"),
		str_arg("i;ascii-numeric"),
	];
	let spec = match_spec(&args);
	// 10 >= 2 numerically (lexically "10" < "2", so this proves numeric order).
	assert!(spec.test_simple("10", "2"));
	assert!(!spec.test_simple("1", "2"));
}

#[test]
fn ascii_numeric_non_number_is_infinity() {
	let args = [
		tag("value"),
		str_arg("gt"),
		tag("comparator"),
		str_arg("i;ascii-numeric"),
	];
	let spec = match_spec(&args);
	// A non-numeric value sorts after every number (RFC 4790 §9.1.1).
	assert!(spec.test_simple("abc", "999999"));
}

#[test]
fn count_rel_and_count_matches() {
	let args = [
		tag("count"),
		str_arg("ge"),
		tag("comparator"),
		str_arg("i;ascii-numeric"),
	];
	let spec = match_spec(&args);
	let rel = spec.count_rel().expect("count rel");
	assert!(spec.count_matches(rel, 3, "2"));
	assert!(!spec.count_matches(rel, 1, "2"));
}

#[test]
fn positional_groups_skip_tag_arguments() {
	// :comparator's "i;octet" and :value's "gt" must not become positional.
	let args = [
		tag("comparator"),
		str_arg("i;octet"),
		tag("value"),
		str_arg("gt"),
		str_arg("Subject"),
		Argument::StrList(vec!["a".to_string(), "b".to_string()]),
	];
	let groups = positional_groups(&args);
	assert_eq!(
		groups,
		vec![
			vec!["Subject".to_string()],
			vec!["a".to_string(), "b".to_string()]
		]
	);
	assert_eq!(
		positional_strings(&args),
		vec!["Subject".to_string(), "a".to_string(), "b".to_string()]
	);
}

#[test]
fn matches_captures_into_vars() {
	let args = [tag("matches")];
	let spec = match_spec(&args);
	let mut vars = HashMap::new();
	assert!(spec.test("bob@example.net", "*@*", &mut vars));
	assert_eq!(vars.get("1").map(String::as_str), Some("bob"));
	assert_eq!(vars.get("2").map(String::as_str), Some("example.net"));
}
