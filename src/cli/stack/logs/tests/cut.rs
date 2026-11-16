use super::super::line::{LINE_LIMIT, cut, stamp_of};

#[test]
fn a_short_line_is_left_alone() {
	let line = "mail-1 | 2026-11-15T20:11:29-05:00 queue is empty";
	assert_eq!(cut(line, LINE_LIMIT, 0), line);
}

#[test]
fn a_long_message_is_cut_after_the_name_and_the_time_and_says_how_much() {
	let message = "x".repeat(LINE_LIMIT + 37);
	let line = format!("mail-1 | 2026-11-15T20:11:29-05:00 {message}");
	let cut = cut(&line, LINE_LIMIT, 0);
	let expected = format!(
		"mail-1 | 2026-11-15T20:11:29-05:00 {} [37 more bytes cut; --raw shows them]",
		"x".repeat(LINE_LIMIT)
	);
	assert_eq!(cut, expected);
}

#[test]
fn a_message_of_exactly_the_limit_is_not_cut() {
	let line = format!("db-1 | {}", "y".repeat(LINE_LIMIT));
	assert_eq!(cut(&line, LINE_LIMIT, 0), line);
}

#[test]
fn the_cut_never_splits_a_character() {
	let line = format!("db-1 | {}", "é".repeat(LINE_LIMIT + 2));
	let cut = cut(&line, LINE_LIMIT, 0);
	assert!(cut.contains(&"é".repeat(LINE_LIMIT)));
	assert!(cut.contains("[4 more bytes cut"));
}

#[test]
fn a_line_with_no_container_name_is_cut_from_its_start() {
	let line = "z".repeat(LINE_LIMIT + 1);
	assert!(cut(&line, LINE_LIMIT, 0).ends_with("[1 more bytes cut; --raw shows them]"));
}

#[test]
fn the_time_is_read_after_the_container_name() {
	assert_eq!(
		stamp_of("a-1 | 2026-11-15T00:00:00Z hi"),
		Some(1_794_700_800_000_000_000)
	);
	assert_eq!(stamp_of("a-1 | the rest of a message"), None);
}

#[test]
fn bytes_the_reader_dropped_are_counted_in_the_mark() {
	let line = format!("db-1 | {}", "w".repeat(LINE_LIMIT));
	assert!(cut(&line, LINE_LIMIT, 1000).ends_with(" [1000 more bytes cut; --raw shows them]"));
	assert!(
		cut("db-1 | short", LINE_LIMIT, 7).ends_with("short [7 more bytes cut; --raw shows them]")
	);
}
