//! Parsing of SEARCH criteria, dates and sequence sets.

use super::*;

#[test]
fn parses_search_or_not() {
	use crate::imap::mailbox::Flag;

	let cmd = parse("a1 SEARCH OR SEEN FLAGGED", DEFAULT_APPEND_LIMIT).expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search {
				ref criteria,
				uid: false,
				..
			} if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Or(a, b)
					if **a == SearchKey::FlagIs(Flag::Seen, true)
						&& **b == SearchKey::FlagIs(Flag::Flagged, true)
				)
		),
		"{:?}",
		cmd.command
	);

	let cmd = parse("a2 SEARCH NOT SEEN", DEFAULT_APPEND_LIMIT).expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Not(k) if **k == SearchKey::FlagIs(Flag::Seen, true)
				)
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_search_date_and_size() {
	let cmd = parse("a1 SEARCH BEFORE 1-Jan-2024", DEFAULT_APPEND_LIMIT).expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::Before(2024, 1, 1))
		),
		"{:?}",
		cmd.command
	);

	let cmd = parse(
		"a2 SEARCH SINCE 15-Jun-2023 SMALLER 1000",
		DEFAULT_APPEND_LIMIT,
	)
	.expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::Since(2023, 6, 15))
				&& matches!(criteria[1], SearchKey::Smaller(1000))
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_search_nested_paren_group() {
	use crate::imap::mailbox::Flag;

	// OR (NOT SEEN) FLAGGED
	let cmd = parse("a1 SEARCH OR (NOT SEEN) FLAGGED", DEFAULT_APPEND_LIMIT).expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Or(a, b)
					if matches!(
						a.as_ref(),
						SearchKey::And(keys)
						if keys.len() == 1
							&& matches!(&keys[0], SearchKey::Not(k) if **k == SearchKey::FlagIs(Flag::Seen, true))
					)
					&& **b == SearchKey::FlagIs(Flag::Flagged, true)
				)
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_imap_date() {
	assert_eq!(super::parse_imap_date("1-Jan-2024"), Some((2024, 1, 1)));
	assert_eq!(super::parse_imap_date("31-Dec-1999"), Some((1999, 12, 31)));
	assert_eq!(super::parse_imap_date("15-Jun-2023"), Some((2023, 6, 15)));
	assert_eq!(super::parse_imap_date("01-Jan-2024"), Some((2024, 1, 1)));
	assert_eq!(super::parse_imap_date("1-Bad-2024"), None);
	assert_eq!(super::parse_imap_date("0-Jan-2024"), None);
}

#[test]
fn search_with_no_criteria_is_bad_arguments() {
	assert!(matches!(
		parse("t1 SEARCH", DEFAULT_APPEND_LIMIT),
		Err(ParseError::BadArguments(_))
	));
}

#[test]
fn parses_search_on_date_criterion() {
	let cmd = parse("a1 SEARCH ON 1-Jan-2024", DEFAULT_APPEND_LIMIT).expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::On(2024, 1, 1))
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn sequence_set_reversed_range_is_normalized() {
	let set = super::parse_sequence_set("5:2").expect("parse");
	// start > end → still matches values within [2, 5]
	assert!(set.contains(2, 10, &[]));
	assert!(set.contains(5, 10, &[]));
	assert!(set.contains(3, 10, &[]));
	assert!(!set.contains(6, 10, &[]));
}

#[test]
fn parse_sequence_set_empty_input_returns_none() {
	assert_eq!(super::parse_sequence_set(""), None);
}
