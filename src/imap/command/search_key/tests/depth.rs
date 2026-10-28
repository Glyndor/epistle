//! Search keys nest at most `MAX_SEARCH_DEPTH` levels.

use super::super::super::{Command, DEFAULT_APPEND_LIMIT, ParseError, parse};
use super::MAX_SEARCH_DEPTH;

fn search(criteria: &str) -> Result<Command, ParseError> {
	parse(&format!("a1 SEARCH {criteria}"), DEFAULT_APPEND_LIMIT).map(|tagged| tagged.command)
}

fn parens(levels: usize) -> String {
	format!("{}ALL{}", "(".repeat(levels), ")".repeat(levels))
}

#[test]
fn groups_nest_up_to_the_limit() {
	assert!(search(&parens(MAX_SEARCH_DEPTH - 1)).is_ok());
	assert_eq!(
		search(&parens(MAX_SEARCH_DEPTH)),
		Err(ParseError::BadArguments("a1".into()))
	);
}

#[test]
fn not_and_or_count_as_levels() {
	let nots = |levels| format!("{}ALL", "NOT ".repeat(levels));
	assert!(search(&nots(MAX_SEARCH_DEPTH - 1)).is_ok());
	assert!(search(&nots(MAX_SEARCH_DEPTH)).is_err());
	let ors = |levels| format!("{}ALL{}", "OR ".repeat(levels), " ALL".repeat(levels));
	assert!(search(&ors(MAX_SEARCH_DEPTH - 1)).is_ok());
	assert!(search(&ors(MAX_SEARCH_DEPTH)).is_err());
}

#[test]
fn a_line_of_nested_groups_is_bad_not_a_crash() {
	// Fills a whole command line with nesting, far past the limit.
	let levels = (crate::imap::command::MAX_COMMAND_LINE - 16) / 2;
	assert!(search(&parens(levels)).is_err());
	assert!(search(&format!("{}ALL", "NOT ".repeat(levels / 2))).is_err());
}
