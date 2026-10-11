//! Tests for the time parsers.

use super::{parse_clamd_date, parse_rfc3339};

#[test]
fn rfc3339_handles_utc_offsets_and_fractions() {
	assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
	assert_eq!(parse_rfc3339("2026-10-09T08:00:00Z"), Some(1_791_532_800));
	assert_eq!(
		parse_rfc3339("2026-10-09T10:00:00.123456789+02:00"),
		Some(1_791_532_800)
	);
	assert_eq!(
		parse_rfc3339("2026-10-09T03:00:00-05:00"),
		Some(1_791_532_800)
	);
	assert_eq!(parse_rfc3339("not a time"), None);
	assert_eq!(parse_rfc3339("2026-13-09T08:00:00Z"), None);
}

#[test]
fn clamd_dates_are_utc_and_tolerate_the_padded_day() {
	assert_eq!(
		parse_clamd_date("Fri Oct  9 08:00:00 2026"),
		Some(1_791_532_800)
	);
	assert_eq!(
		parse_clamd_date("Fri Oct 09 08:00:00 2026"),
		Some(1_791_532_800)
	);
	assert_eq!(parse_clamd_date("Fri Foo  9 08:00:00 2026"), None);
	assert_eq!(parse_clamd_date(""), None);
}
