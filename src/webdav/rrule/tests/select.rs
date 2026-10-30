//! Tests of the rules that select days and of the series that start on the
//! 29th to the 31st.

use super::{civil_from_secs, expand, parse_datetime, parse_rule};

fn dt(value: &str) -> i64 {
	parse_datetime(value).expect("valid datetime")
}

fn days(start: &str, rule: &str, from: &str, to: &str) -> Vec<String> {
	let rule = parse_rule(rule).expect("rule");
	expand(dt(start), Some(&rule), dt(from), dt(to))
		.into_iter()
		.map(|at| {
			let (y, m, d) = civil_from_secs(at);
			format!("{y:04}{m:02}{d:02}")
		})
		.collect()
}

#[test]
fn weekly_on_listed_weekdays() {
	// Monday 5 January 2026.
	assert_eq!(
		days(
			"20260105T090000Z",
			"FREQ=WEEKLY;BYDAY=MO,WE",
			"20260101T000000Z",
			"20260121T000000Z"
		),
		["20260105", "20260107", "20260112", "20260114", "20260119"]
	);
	// Every other week, and a start in the middle of the week.
	assert_eq!(
		days(
			"20260107T090000Z",
			"FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE",
			"20260101T000000Z",
			"20260201T000000Z"
		),
		["20260107", "20260119", "20260121"]
	);
}

#[test]
fn the_week_start_decides_which_days_an_interval_groups() {
	// Sunday 4 and Monday 5 January with INTERVAL=2: with weeks starting on
	// Monday the Sunday is the end of one week, with Sunday it begins one.
	let monday = days(
		"20260104T090000Z",
		"FREQ=WEEKLY;INTERVAL=2;BYDAY=SU,MO;WKST=MO",
		"20260101T000000Z",
		"20260131T000000Z",
	);
	let sunday = days(
		"20260104T090000Z",
		"FREQ=WEEKLY;INTERVAL=2;BYDAY=SU,MO;WKST=SU",
		"20260101T000000Z",
		"20260131T000000Z",
	);
	assert_eq!(monday, ["20260104", "20260112", "20260118", "20260126"]);
	assert_eq!(sunday, ["20260104", "20260105", "20260118", "20260119"]);
}

#[test]
fn count_and_until_apply_to_selected_days() {
	assert_eq!(
		days(
			"20260105T090000Z",
			"FREQ=WEEKLY;BYDAY=MO,WE;COUNT=3",
			"20260101T000000Z",
			"20260301T000000Z"
		),
		["20260105", "20260107", "20260112"]
	);
	assert_eq!(
		days(
			"20260105T090000Z",
			"FREQ=WEEKLY;BYDAY=MO,WE;UNTIL=20260112T090000Z",
			"20260101T000000Z",
			"20260301T000000Z"
		),
		["20260105", "20260107", "20260112"]
	);
	// A count spent long before the window leaves nothing in it.
	assert!(
		days(
			"20100105T090000Z",
			"FREQ=WEEKLY;BYDAY=MO;COUNT=5",
			"20260101T000000Z",
			"20260201T000000Z"
		)
		.is_empty()
	);
}

#[test]
fn daily_with_a_weekday_or_month_filter() {
	assert_eq!(
		days(
			"20260105T090000Z",
			"FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR",
			"20260105T000000Z",
			"20260113T000000Z"
		),
		[
			"20260105", "20260106", "20260107", "20260108", "20260109", "20260112"
		]
	);
	assert_eq!(
		days(
			"20260105T090000Z",
			"FREQ=DAILY;BYMONTHDAY=15,-1",
			"20260101T000000Z",
			"20260301T000000Z"
		),
		["20260115", "20260131", "20260215", "20260228"]
	);
}

#[test]
fn monthly_by_ordinal_weekday_and_by_month_day() {
	assert_eq!(
		days(
			"20260113T090000Z",
			"FREQ=MONTHLY;BYDAY=2TU",
			"20260101T000000Z",
			"20260401T000000Z"
		),
		["20260113", "20260210", "20260310"]
	);
	// The last Friday: 30 January, 27 February, 27 March (2 January is not it).
	assert_eq!(
		days(
			"20260102T090000Z",
			"FREQ=MONTHLY;BYDAY=-1FR",
			"20260101T000000Z",
			"20260401T000000Z"
		),
		["20260130", "20260227", "20260327"]
	);
	assert_eq!(
		days(
			"20260101T090000Z",
			"FREQ=MONTHLY;BYMONTHDAY=-1",
			"20260101T000000Z",
			"20260401T000000Z"
		),
		["20260131", "20260228", "20260331"]
	);
	// The 31st is skipped in the months that lack it.
	assert_eq!(
		days(
			"20260131T090000Z",
			"FREQ=MONTHLY;BYMONTHDAY=31",
			"20260101T000000Z",
			"20260501T000000Z"
		),
		["20260131", "20260331"]
	);
}

#[test]
fn yearly_by_month() {
	assert_eq!(
		days(
			"20260315T090000Z",
			"FREQ=YEARLY;BYMONTH=3,9",
			"20260101T000000Z",
			"20281231T000000Z"
		),
		[
			"20260315", "20260915", "20270315", "20270915", "20280315", "20280915"
		]
	);
	assert_eq!(
		days(
			"20260301T090000Z",
			"FREQ=YEARLY;BYMONTH=3;BYDAY=1MO",
			"20260101T000000Z",
			"20281231T000000Z"
		),
		["20260302", "20270301", "20280306"]
	);
}

#[test]
fn rules_that_are_not_evaluated_are_flagged() {
	for text in [
		"FREQ=MONTHLY;BYSETPOS=1;BYDAY=MO",
		"FREQ=YEARLY;BYWEEKNO=3",
		"FREQ=WEEKLY;BYYEARDAY=3",
		"FREQ=DAILY;BYHOUR=9",
		"FREQ=YEARLY;BYDAY=MO",
		"FREQ=WEEKLY;BYDAY=2MO",
		"FREQ=DAILY;BYDAY=XX",
		"FREQ=WEEKLY;BYMONTHDAY=1",
	] {
		assert!(!super::fully_supported(text), "{text}");
	}
	for text in [
		"FREQ=WEEKLY;BYDAY=MO,WE",
		"FREQ=MONTHLY;BYDAY=-1FR",
		"FREQ=YEARLY;BYMONTH=3;BYMONTHDAY=15",
		"FREQ=WEEKLY;INTERVAL=2;COUNT=3;WKST=MO;UNTIL=20300101T000000Z",
	] {
		assert!(super::fully_supported(text), "{text}");
	}
}

#[test]
fn a_budget_that_runs_out_is_reported() {
	let rule = parse_rule("FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR,SA,SU").expect("rule");
	let (found, exceeded) = super::expand_bounded(
		dt("20260101T000000Z"),
		Some(&rule),
		dt("20260101T000000Z"),
		dt("20300101T000000Z"),
		50,
	);
	assert!(exceeded);
	assert!(found.len() <= 50);
}

// A series that starts on the 29th, 30th or 31st recurs only in the months that
// have the day (RFC 5545 §3.3.10). These cases are written by hand from the
// calendar, not produced by the code under test.
#[test]
fn a_series_from_the_31st_skips_the_months_without_it() {
	assert_eq!(
		days(
			"20260131T090000Z",
			"FREQ=MONTHLY",
			"20260101T000000Z",
			"20260901T000000Z"
		),
		["20260131", "20260331", "20260531", "20260731", "20260831"]
	);
	// COUNT counts the occurrences that exist, not the months passed.
	assert_eq!(
		days(
			"20260131T090000Z",
			"FREQ=MONTHLY;COUNT=4",
			"20260101T000000Z",
			"20300101T000000Z"
		),
		["20260131", "20260331", "20260531", "20260731"]
	);
	assert_eq!(
		days(
			"20260131T090000Z",
			"FREQ=MONTHLY;INTERVAL=3",
			"20260101T000000Z",
			"20261101T000000Z"
		),
		["20260131", "20260731", "20261031"]
	);
	assert_eq!(
		days(
			"20260131T090000Z",
			"FREQ=MONTHLY;UNTIL=20260501T000000Z",
			"20260101T000000Z",
			"20261101T000000Z"
		),
		["20260131", "20260331"]
	);
}

#[test]
fn a_series_from_the_30th_or_29th_skips_february() {
	assert_eq!(
		days(
			"20260130T090000Z",
			"FREQ=MONTHLY",
			"20260101T000000Z",
			"20260601T000000Z"
		),
		["20260130", "20260330", "20260430", "20260530"]
	);
	assert_eq!(
		days(
			"20260129T090000Z",
			"FREQ=MONTHLY",
			"20260101T000000Z",
			"20260501T000000Z"
		),
		["20260129", "20260329", "20260429"]
	);
	// 2028 is a leap year.
	assert_eq!(
		days(
			"20280129T090000Z",
			"FREQ=MONTHLY",
			"20280101T000000Z",
			"20280501T000000Z"
		),
		["20280129", "20280229", "20280329", "20280429"]
	);
}

#[test]
fn a_series_from_the_29th_of_february_recurs_in_leap_years() {
	assert_eq!(
		days(
			"20240229T090000Z",
			"FREQ=YEARLY",
			"20240101T000000Z",
			"20330101T000000Z"
		),
		["20240229", "20280229", "20320229"]
	);
	assert_eq!(
		days(
			"20240229T090000Z",
			"FREQ=YEARLY;COUNT=2",
			"20240101T000000Z",
			"20400101T000000Z"
		),
		["20240229", "20280229"]
	);
	// A start on another day of February is unaffected.
	assert_eq!(
		days(
			"20240228T090000Z",
			"FREQ=YEARLY",
			"20240101T000000Z",
			"20270101T000000Z"
		),
		["20240228", "20250228", "20260228"]
	);
}

#[test]
fn a_monthly_series_before_the_29th_is_unchanged() {
	assert_eq!(
		days(
			"20260115T090000Z",
			"FREQ=MONTHLY",
			"20260101T000000Z",
			"20260401T000000Z"
		),
		["20260115", "20260215", "20260315"]
	);
}
