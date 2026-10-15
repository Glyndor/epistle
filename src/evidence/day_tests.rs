use super::*;

#[test]
fn names_and_parses_round_trip() {
	for day in [-1, 0, 1, 19_000, 20_740, 30_000] {
		assert_eq!(Day::parse(&Day(day).name()), Some(Day(day)));
	}
	assert_eq!(Day(0).name(), "1970-01-01");
	assert_eq!(Day::of_epoch(86_399), Day(0));
	assert_eq!(Day::of_epoch(86_400), Day(1));
}

#[test]
fn refuses_what_is_not_a_calendar_date() {
	for bad in [
		"2026-02-30",
		"2026-13-01",
		"2026-1-01",
		"../../etc",
		"2026-10-1x",
		"+026-10-14",
		"",
	] {
		assert_eq!(Day::parse(bad), None, "{bad}");
	}
}
