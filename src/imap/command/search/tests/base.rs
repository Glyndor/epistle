
use super::*;

#[test]
fn find_close_paren_handles_unbalanced_close() {
	// A `)` with no matching `(` must not overflow the unsigned depth
	// counter — it is unbalanced input, so there is no closing index.
	assert_eq!(find_close_paren(")"), None);
	assert_eq!(find_close_paren("))"), None);
	assert_eq!(find_close_paren("a) b"), None);
}

#[test]
fn find_close_paren_matches_the_opener() {
	assert_eq!(find_close_paren("()"), Some(1));
	assert_eq!(find_close_paren("(a (b) c) d"), Some(8));
}

#[test]
fn search_parse_never_panics_on_the_fuzz_crash() {
	// Regression for the fuzzer-found subtract-with-overflow: a malformed
	// SEARCH/ESEARCH line with a stray `)` before any `(` must return an
	// error, not panic.
	let crash = "E-- SEARCH       return   m E-) ESEARCH  HEADER EFFFFn   TMETFYm Y";
	let _ = super::super::super::parse(crash, super::super::super::DEFAULT_APPEND_LIMIT);
}
