//! Tests for reading and showing an API key expiry.

use super::*;

/// 2026-10-24T00:00:00Z.
const NOW: u64 = 1_792_800_000;

#[test]
fn an_epoch_passes_through_unchanged() {
	assert_eq!(at("1700000000", NOW), Ok(1_700_000_000));
	assert_eq!(at("4102444800", NOW), Ok(4_102_444_800));
}

#[test]
fn a_date_is_midnight_utc() {
	assert_eq!(at("2027-01-01", NOW), Ok(1_798_761_600));
}

#[test]
fn an_rfc3339_instant_honours_its_zone_and_drops_the_fraction() {
	assert_eq!(at("2027-01-01T00:00:00Z", NOW), Ok(1_798_761_600));
	assert_eq!(at("2027-01-01T02:00:00+02:00", NOW), Ok(1_798_761_600));
	assert_eq!(at("2026-12-31T19:00:00.750-05:00", NOW), Ok(1_798_761_600));
}

#[test]
fn a_duration_counts_from_now_in_both_flags() {
	assert_eq!(at("90d", NOW), Ok(NOW + 90 * 86_400));
	assert_eq!(within("2w", NOW), Ok(NOW + 14 * 86_400));
	assert_eq!(within("36h", NOW), Ok(NOW + 36 * 3600));
}

#[test]
fn a_date_in_the_past_is_refused() {
	assert!(at("2020-01-01", NOW).unwrap_err().contains("past"));
	assert!(at("2026-10-23T23:59:59Z", NOW).is_err());
}

#[test]
fn a_bare_number_is_an_epoch_only_when_it_could_be_one() {
	for bad in ["2027", "20270131", "999999999", "1798761600000"] {
		let error = at(bad, NOW).unwrap_err();
		assert!(
			error.contains("2027-01-31") && error.contains("90d"),
			"{error}"
		);
	}
	assert_eq!(at("253402300799", NOW), Ok(253_402_300_799));
}

#[test]
fn a_huge_duration_and_an_instant_before_1970_are_refused() {
	assert!(
		within("5000000000000d", NOW)
			.unwrap_err()
			.contains("too far")
	);
	assert!(at("1969-12-31", NOW).unwrap_err().contains("past"));
	assert!(
		at("1970-01-01T00:00:00+02:00", NOW)
			.unwrap_err()
			.contains("past")
	);
}

#[test]
fn a_leap_second_is_accepted() {
	assert_eq!(
		at("2027-12-31T23:59:60Z", NOW),
		at("2028-01-01T00:00:00Z", NOW)
	);
}

#[test]
fn an_epoch_past_year_9999_is_shown_as_the_number() {
	assert_eq!(describe(u64::MAX, NOW), u64::MAX.to_string());
	assert_eq!(
		status_warning(0, u64::MAX).as_deref(),
		Some("expired on 1970-01-01T00:00:00Z")
	);
}

#[test]
fn nonsense_is_refused() {
	for bad in [
		"",
		"tomorrow",
		"2027-13-01",
		"2027-02-30",
		"2027-1-1",
		"2027-01-01T00:00:00",
		"2027-01-01T25:00:00Z",
		"2027-01-01T00:00:00+2:00",
		"0d",
		"10x",
		"d",
		"-5d",
	] {
		assert!(at(bad, NOW).is_err(), "{bad:?} should be refused");
	}
	assert!(within("90", NOW).is_err(), "a bare number has no unit");
	assert!(within("99999999999999999999d", NOW).is_err());
}

#[test]
fn list_shows_a_readable_instant_and_marks_a_passed_one() {
	assert_eq!(describe(1_798_761_600, NOW), "2027-01-01T00:00:00Z");
	assert_eq!(
		describe(1_700_000_000, NOW),
		"2023-11-14T22:13:20Z (expired)"
	);
}

#[test]
fn status_warns_only_inside_the_window() {
	assert_eq!(
		status_warning(NOW + 86_400, NOW).as_deref(),
		Some("expires in 1 day, on 2026-10-25T00:00:00Z")
	);
	assert!(status_warning(NOW + WARN_WITHIN - 1, NOW).is_some());
	assert!(status_warning(NOW + WARN_WITHIN, NOW).is_none());
	assert_eq!(
		status_warning(NOW, NOW).as_deref(),
		Some("expired on 2026-10-24T00:00:00Z")
	);
}
