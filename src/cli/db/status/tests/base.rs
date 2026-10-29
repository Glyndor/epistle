//! Reading the answer of the status query.

use crate::cli::db::status::tests::{MAX_VERSION, Status, parse};

#[test]
fn a_well_formed_answer_is_read() {
	assert_eq!(
		parse("16.4 (Debian 16.4-1)|8192000|12|3|100\n").unwrap(),
		Status {
			database: "epistle",
			version: "16.4 (Debian 16.4-1)".into(),
			size_bytes: 8_192_000,
			tables: 12,
			connections: 3,
			max_connections: 100,
		}
	);
}

#[test]
fn anything_else_is_refused_with_the_answer_shortened_and_escaped() {
	for answer in [
		"",
		"16.4|1|2|3",
		"16.4|1|2|3|4|5",
		"16.4|x|2|3|4",
		"16.4|-1|2|3|4",
		"16.4|+1|2|3|4",
		"16.4|1|2|3|99999999999999999999999",
		"|1|2|3|4",
	] {
		let error = parse(answer).unwrap_err();
		assert!(
			error.starts_with("unexpected answer from the database: "),
			"{answer:?}: {error}"
		);
	}
	let error = parse(&format!("{}\u{1b}[2J", "x".repeat(200))).unwrap_err();
	assert!(!error.contains('\u{1b}') && error.len() < 120, "{error}");
	assert!(parse(&format!("{}|1|2|3|4", "v".repeat(MAX_VERSION + 1))).is_err());
	assert!(parse(&format!("{}|1|2|3|4", "v".repeat(MAX_VERSION))).is_ok());
}
