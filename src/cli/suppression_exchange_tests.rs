//! The CSV the suppression exchange reads and writes.

use super::{MAX_ENTRIES, parse, parse_row, reason_problem, split, unquote_formula};
use crate::cli::csv::field;

const NOW: u64 = 1_800_000_000;

#[test]
fn split_reads_quoted_fields_with_doubled_quotes() {
	assert_eq!(
		split("a@example.net,2026-01-02T03:04:05Z,\"said \"\"no\"\", twice\"").unwrap(),
		vec![
			"a@example.net",
			"2026-01-02T03:04:05Z",
			"said \"no\", twice"
		]
	);
	assert_eq!(
		split("a@example.net,,").unwrap(),
		vec!["a@example.net", "", ""]
	);
	assert_eq!(split("").unwrap(), vec![""]);
}

#[test]
fn split_refuses_a_broken_quote() {
	assert_eq!(
		split("a,\"open").unwrap_err(),
		"a quoted field is not closed"
	);
	assert_eq!(
		split("a,\"x\"y").unwrap_err(),
		"text follows a closing quote"
	);
	assert_eq!(
		split("a,x\"y").unwrap_err(),
		"a quote inside an unquoted field"
	);
}

#[test]
fn a_formula_is_exported_with_an_apostrophe_and_imported_without() {
	for text in ["=1+1", "+1", "-1", "@SUM(A1)"] {
		let exported = field(text);
		assert_eq!(exported, format!("'{text}"));
		assert_eq!(unquote_formula(&exported), text);
	}
	assert_eq!(unquote_formula("'quoted"), "'quoted");
	assert_eq!(unquote_formula("plain"), "plain");
}

#[test]
fn a_row_needs_a_real_address_and_a_storable_reason() {
	let row = parse_row("A@Example.NET,2026-01-02T03:04:05Z,why", NOW).unwrap();
	assert_eq!(
		(row.address.as_str(), row.since, row.reason.as_deref()),
		("a@example.net", Some(1_767_323_045), Some("why"))
	);
	assert!(parse_row("not an address", NOW).is_err());
	assert!(parse_row("a@example.net,yesterday", NOW).is_err());
	assert_eq!(
		parse_row("a@example.net,,\"x\u{1b}y\"", NOW).unwrap_err(),
		"the reason must not contain control characters"
	);
	assert_eq!(
		parse_row("a@example.net,,b,c", NOW).unwrap_err(),
		"more than three fields (address, since, reason)"
	);
}

#[test]
fn a_time_in_the_future_is_clamped_to_now() {
	let row = parse_row("a@example.net,2999-01-01T00:00:00Z", NOW).unwrap();
	assert_eq!(row.since, Some(NOW));
}

#[test]
fn reasons_are_bounded() {
	assert_eq!(reason_problem(&"x".repeat(512)), None);
	assert_eq!(
		reason_problem(&"x".repeat(513)).unwrap(),
		"the reason must be at most 512 characters"
	);
	assert_eq!(
		reason_problem("a\nb").unwrap(),
		"the reason must not contain control characters"
	);
}

#[test]
fn parse_skips_comments_blank_lines_a_header_and_a_bom() {
	let text =
		"\u{feff}address,since,reason\r\n# note\r\n\r\na@example.net\r\nb@example.net,,x\r\n";
	let rows = parse(text, NOW).unwrap();
	let addresses: Vec<&str> = rows.iter().map(|row| row.address.as_str()).collect();
	assert_eq!(addresses, vec!["a@example.net", "b@example.net"]);
}

#[test]
fn parse_names_each_bad_line_up_to_ten() {
	let text: String = (0..15).map(|n| format!("bad{n}\n")).collect();
	let problems = parse(&text, NOW).unwrap_err();
	assert_eq!(problems.len(), 10);
	assert!(problems[0].starts_with("line 1: "), "{}", problems[0]);
	assert!(problems[9].starts_with("line 10: "), "{}", problems[9]);
}

#[test]
fn parse_stops_at_the_entry_limit() {
	let text = "a@example.net\n".repeat(MAX_ENTRIES + 1);
	assert_eq!(
		parse(&text, NOW).unwrap_err(),
		vec!["more than 100000 entries; split the file".to_string()]
	);
	assert_eq!(
		parse(&"a@example.net\n".repeat(MAX_ENTRIES), NOW)
			.unwrap()
			.len(),
		MAX_ENTRIES
	);
}

#[test]
fn a_repeated_address_with_other_case_is_one_entry() {
	let rows = parse("A@Example.net\na@example.NET\n", NOW).unwrap();
	assert_eq!(rows[0].address, rows[1].address);
}
