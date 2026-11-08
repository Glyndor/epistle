//! The `--since` filter and the RFC 3339 timestamp it parses.

use super::*;

#[test]
fn parse_since_accepts_durations_and_rfc3339_and_rejects_garbage() {
	let now = 1_700_000_000;
	assert_eq!(parse_since("", now).expect("empty"), None);
	assert_eq!(parse_since("24h", now).expect("24h"), Some(now - 24 * 3600));
	assert_eq!(parse_since("7d", now).expect("7d"), Some(now - 7 * 86_400));
	assert_eq!(parse_since("30m", now).expect("30m"), Some(now - 30 * 60));
	assert_eq!(parse_since("5s", now).expect("5s"), Some(now - 5));
	// 2024-01-02T03:04:05Z = 1704164645 epoch seconds
	assert_eq!(
		parse_since("2024-01-02T03:04:05Z", now).expect("rfc3339"),
		Some(1_704_164_645)
	);
	// `+02:00` offset: 03:04:05 local is 01:04:05 UTC.
	assert_eq!(
		parse_since("2024-01-02T03:04:05+02:00", now).expect("offset"),
		Some(1_704_157_445)
	);
	// Negative offset: 03:04:05-05:00 is 08:04:05 UTC.
	assert_eq!(
		parse_since("2024-01-02T03:04:05-05:00", now).expect("negative offset"),
		Some(1_704_182_645)
	);
	assert!(parse_since("not-a-time", now).is_err());
	assert!(parse_since("2024-13-40T99:99:99Z", now).is_err());
}

#[test]
fn rfc3339_times_must_be_real_calendar_times() {
	let now = 1_700_000_000;
	for good in [
		"2024-02-29T00:00:00Z",
		"2026-02-28T23:59:59Z",
		"2026-12-31T00:00:00+23:59",
		"1970-01-01T00:00:00Z",
	] {
		assert!(parse_since(good, now).is_ok(), "{good} must be accepted");
	}
	for bad in [
		"2026-02-30T00:00:00Z",
		"2025-02-29T00:00:00Z",
		"2026-04-31T00:00:00Z",
		"2026-06-00T00:00:00Z",
		"99999-01-01T00:00:00Z",
		"2026-01-01T00:00:00+99:99",
		"2026-01-01T00:00:00+24:00",
		"2026-01-01T00:00:00+01:75",
	] {
		assert!(parse_since(bad, now).is_err(), "{bad} must be refused");
	}
}
