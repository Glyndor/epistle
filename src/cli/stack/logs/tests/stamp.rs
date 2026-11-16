use super::super::stamp::parse;

const SECOND: i128 = 1_000_000_000;

#[test]
fn the_epoch_is_zero() {
	assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
}

#[test]
fn a_known_day_in_utc() {
	// 2026-11-15T20:11:29Z, counted with `date -u -d ... +%s`.
	assert_eq!(parse("2026-11-15T20:11:29Z"), Some(1_794_773_489 * SECOND));
}

#[test]
fn an_offset_is_taken_off_so_two_zones_compare() {
	let local = parse("2026-11-15T20:11:29-05:00").expect("parses");
	let utc = parse("2026-11-16T01:11:29Z").expect("parses");
	assert_eq!(local, utc);
	assert_eq!(
		parse("2026-11-15T20:11:29+01:30"),
		parse("2026-11-15T18:41:29Z")
	);
}

#[test]
fn the_fraction_orders_two_lines_in_the_same_second() {
	let first = parse("2026-11-15T20:11:29.000000001Z").expect("parses");
	let second = parse("2026-11-15T20:11:29.5Z").expect("parses");
	assert_eq!(second - first, 500_000_000 - 1);
}

#[test]
fn a_leap_day_counts() {
	let before = parse("2028-02-29T00:00:00Z").expect("parses");
	let after = parse("2028-03-01T00:00:00Z").expect("parses");
	assert_eq!(after - before, 86_400 * SECOND);
}

#[test]
fn words_that_are_not_a_time_are_refused() {
	for word in [
		"",
		"hello",
		"2026-11-15",
		"2026-11-15T20:11:29",
		"2026-13-15T20:11:29Z",
		"2026-11-15T25:11:29Z",
		"2026-11-15T20:11:29.Z",
		"2026-11-15T20:11:29+0500",
		"2026-11-15T20:11:29Zjunk",
		"2026-11-15T2x:11:29Z",
	] {
		assert_eq!(parse(word), None, "{word:?} is not an RFC 3339 time");
	}
}
