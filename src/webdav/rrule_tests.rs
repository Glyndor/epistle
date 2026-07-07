use super::{Freq, civil_from_secs, days_from_civil, expand, parse_datetime, parse_rule};

/// A UTC datetime helper for the tests, panicking on a bad literal.
fn dt(value: &str) -> i64 {
	parse_datetime(value).expect("valid datetime")
}

#[test]
fn days_from_civil_known_dates() {
	// The epoch itself is day zero.
	assert_eq!(days_from_civil(1970, 1, 1), 0);
	// One non-leap year later.
	assert_eq!(days_from_civil(1971, 1, 1), 365);
	// A well-known date: 2000-01-01 is 10957 days after the epoch.
	assert_eq!(days_from_civil(2000, 1, 1), 10_957);
	// Before the epoch is negative.
	assert_eq!(days_from_civil(1969, 12, 31), -1);
}

#[test]
fn parse_datetime_round_trips_to_civil() {
	let secs = dt("20260101T000000Z");
	assert!(secs > 0);
	assert_eq!(civil_from_secs(secs), (2026, 1, 1));
	let noon = dt("20260315T123456Z");
	assert_eq!(civil_from_secs(noon), (2026, 3, 15));
	assert_eq!(noon.rem_euclid(86_400), 12 * 3600 + 34 * 60 + 56);
}

#[test]
fn parse_datetime_date_only_is_midnight() {
	assert_eq!(parse_datetime("20260101"), Some(dt("20260101T000000Z")));
}

#[test]
fn parse_datetime_rejects_malformed() {
	assert_eq!(parse_datetime(""), None);
	assert_eq!(parse_datetime("2026"), None);
	assert_eq!(parse_datetime("20261301T000000Z"), None); // month 13
	assert_eq!(parse_datetime("20260132T000000Z"), None); // day 32
	assert_eq!(parse_datetime("20260101T250000Z"), None); // hour 25
}

#[test]
fn parse_rule_reads_subset() {
	let rule = parse_rule("FREQ=WEEKLY;INTERVAL=2;COUNT=10").expect("rule");
	assert_eq!(rule.freq, Freq::Weekly);
	assert_eq!(rule.interval, 2);
	assert_eq!(rule.count, Some(10));
	assert_eq!(rule.until, None);
}

#[test]
fn parse_rule_rejects_unknown_freq() {
	assert_eq!(parse_rule("FREQ=SECONDLY"), None);
	assert_eq!(parse_rule("INTERVAL=2"), None); // no FREQ
}

#[test]
fn non_recurring_single_occurrence_in_window() {
	let start = dt("20260110T090000Z");
	let got = expand(start, None, dt("20260101T000000Z"), dt("20260201T000000Z"));
	assert_eq!(got, vec![start]);
}

#[test]
fn non_recurring_outside_window_excluded() {
	let start = dt("20260301T090000Z");
	let got = expand(start, None, dt("20260101T000000Z"), dt("20260201T000000Z"));
	assert!(got.is_empty());
}

#[test]
fn daily_expansion_within_window() {
	let start = dt("20260101T080000Z");
	let rule = parse_rule("FREQ=DAILY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260104T000000Z"),
	);
	assert_eq!(
		got,
		vec![
			dt("20260101T080000Z"),
			dt("20260102T080000Z"),
			dt("20260103T080000Z"),
		]
	);
}

#[test]
fn daily_interval_strides() {
	let start = dt("20260101T080000Z");
	let rule = parse_rule("FREQ=DAILY;INTERVAL=3").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260110T000000Z"),
	);
	assert_eq!(
		got,
		vec![
			dt("20260101T080000Z"),
			dt("20260104T080000Z"),
			dt("20260107T080000Z"),
		]
	);
}

#[test]
fn weekly_expansion() {
	let start = dt("20260105T100000Z"); // a Monday
	let rule = parse_rule("FREQ=WEEKLY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260201T000000Z"),
	);
	assert_eq!(
		got,
		vec![
			dt("20260105T100000Z"),
			dt("20260112T100000Z"),
			dt("20260119T100000Z"),
			dt("20260126T100000Z"),
		]
	);
}

#[test]
fn monthly_expansion_preserves_time() {
	let start = dt("20260115T143000Z");
	let rule = parse_rule("FREQ=MONTHLY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260401T000000Z"),
	);
	assert_eq!(
		got,
		vec![
			dt("20260115T143000Z"),
			dt("20260215T143000Z"),
			dt("20260315T143000Z"),
		]
	);
}

#[test]
fn monthly_clamps_short_month() {
	let start = dt("20260131T000000Z");
	let rule = parse_rule("FREQ=MONTHLY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260401T000000Z"),
	);
	// February clamps to the 28th (2026 is not a leap year), March to the 31st.
	assert_eq!(
		got,
		vec![
			dt("20260131T000000Z"),
			dt("20260228T000000Z"),
			dt("20260331T000000Z"),
		]
	);
}

#[test]
fn yearly_expansion() {
	let start = dt("20260220T060000Z");
	let rule = parse_rule("FREQ=YEARLY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20290101T000000Z"),
	);
	assert_eq!(
		got,
		vec![
			dt("20260220T060000Z"),
			dt("20270220T060000Z"),
			dt("20280220T060000Z"),
		]
	);
}

#[test]
fn count_bounds_expansion() {
	let start = dt("20260101T080000Z");
	let rule = parse_rule("FREQ=DAILY;COUNT=2").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260201T000000Z"),
	);
	// COUNT caps the series even though the window holds many more days.
	assert_eq!(got, vec![dt("20260101T080000Z"), dt("20260102T080000Z")]);
}

#[test]
fn until_bounds_expansion() {
	let start = dt("20260101T080000Z");
	let rule = parse_rule("FREQ=DAILY;UNTIL=20260103T080000Z").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260201T000000Z"),
	);
	// UNTIL is inclusive: the 3rd is kept, the 4th is not.
	assert_eq!(
		got,
		vec![
			dt("20260101T080000Z"),
			dt("20260102T080000Z"),
			dt("20260103T080000Z"),
		]
	);
}

#[test]
fn occurrence_before_window_excluded() {
	let start = dt("20251201T080000Z");
	let rule = parse_rule("FREQ=DAILY").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260103T000000Z"),
	);
	// The series starts before the window; only the in-window days appear.
	assert_eq!(got, vec![dt("20260101T080000Z"), dt("20260102T080000Z")]);
}

#[test]
fn count_counts_from_dtstart_not_window() {
	let start = dt("20251230T080000Z");
	let rule = parse_rule("FREQ=DAILY;COUNT=3").expect("rule");
	let got = expand(
		start,
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20260201T000000Z"),
	);
	// Three total occurrences (Dec 30, 31, Jan 1); only Jan 1 is in window.
	assert_eq!(got, vec![dt("20260101T080000Z")]);
}
