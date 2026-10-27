use super::values::{Unit, parse_value};

#[test]
fn limits_parse_sizes_and_durations_to_exact_integers() {
	for (input, unit, expected) in [
		("5G", Unit::Size, 5 * 1024 * 1024 * 1024),
		("2k", Unit::Size, 2048),
		("3M", Unit::Size, 3 * 1024 * 1024),
		("1T", Unit::Size, 1024_u64.pow(4)),
		("1024", Unit::Size, 1024),
		("0", Unit::Size, 0),
		("5d", Unit::Duration, 5 * 86400),
		("12h", Unit::Duration, 12 * 3600),
		("2w", Unit::Duration, 14 * 86400),
		("3m", Unit::Duration, 180),
		("7s", Unit::Duration, 7),
		("0", Unit::Duration, 0),
		("120", Unit::Count, 120),
	] {
		assert_eq!(
			parse_value(input, unit, i64::MAX as u64),
			Ok(expected),
			"limits must convert size and duration suffixes to exact integer units"
		);
	}
}

#[test]
fn limits_reject_invalid_units_signs_fractions_and_overflow() {
	for (input, unit) in [
		("", Unit::Size),
		("-1", Unit::Size),
		("+1", Unit::Size),
		("1.5G", Unit::Size),
		("1GB", Unit::Size),
		("1h", Unit::Size),
		("1G", Unit::Duration),
		("1h30m", Unit::Duration),
		(" 5d", Unit::Duration),
		("5d ", Unit::Duration),
		("1k", Unit::Count),
		("18446744073709551616", Unit::Size),
		("18446744073709551615G", Unit::Size),
		("18446744073709551615w", Unit::Duration),
	] {
		assert_eq!(
			parse_value(input, unit, i64::MAX as u64),
			Err("expected a non-negative integer with a supported suffix within the field range"),
			"limits must reject malformed or overflowing values with a precise diagnostic"
		);
	}
	assert_eq!(
		parse_value("4294967295", Unit::Count, u32::MAX as u64),
		Ok(u32::MAX as u64)
	);
	assert_eq!(
		parse_value("4294967296", Unit::Count, u32::MAX as u64),
		Err("expected a non-negative integer with a supported suffix within the field range"),
		"limits must reject counts outside the config field range"
	);
}
