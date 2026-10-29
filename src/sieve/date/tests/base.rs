use super::*;

const DATE: &str = "Wed, 17 Jun 2026 14:30:05 +0000";

#[test]
fn extracts_each_part() {
	assert_eq!(extract_part(DATE, "year").as_deref(), Some("2026"));
	assert_eq!(extract_part(DATE, "month").as_deref(), Some("06"));
	assert_eq!(extract_part(DATE, "day").as_deref(), Some("17"));
	assert_eq!(extract_part(DATE, "hour").as_deref(), Some("14"));
	assert_eq!(extract_part(DATE, "minute").as_deref(), Some("30"));
	assert_eq!(extract_part(DATE, "second").as_deref(), Some("05"));
	assert_eq!(extract_part(DATE, "date").as_deref(), Some("2026-06-17"));
	assert_eq!(extract_part(DATE, "time").as_deref(), Some("14:30:05"));
}

#[test]
fn handles_missing_weekday_and_seconds() {
	assert_eq!(
		extract_part("1 Jan 2000 00:00", "date").as_deref(),
		Some("2000-01-01")
	);
}

#[test]
fn rejects_garbage_and_unknown_parts() {
	assert!(extract_part("not a date", "year").is_none());
	assert!(extract_part(DATE, "weekday").is_none());
}

#[test]
fn unix_components_match_known_timestamp() {
	// 1781724605 = 2026-06-17 19:30:05 UTC.
	let ts = 1_781_724_605;
	assert_eq!(
		extract_part_from_unix(ts, "date").as_deref(),
		Some("2026-06-17")
	);
	assert_eq!(
		extract_part_from_unix(ts, "time").as_deref(),
		Some("19:30:05")
	);
	assert_eq!(extract_part_from_unix(ts, "year").as_deref(), Some("2026"));
	// Epoch.
	assert_eq!(
		extract_part_from_unix(0, "date").as_deref(),
		Some("1970-01-01")
	);
}
