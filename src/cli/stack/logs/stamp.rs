//! The RFC 3339 time podup puts before each line when asked for `-t`, as a
//! number of nanoseconds that sorts.

/// Nanoseconds since the Unix epoch of `token`
/// (`2026-11-15T20:11:29.123456789-05:00`, `Z` for UTC), or `None` when it
/// is not a time in that form. The fraction is optional.
pub(super) fn parse(token: &str) -> Option<i128> {
	let bytes = token.as_bytes();
	if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
		return None;
	}
	if bytes[13] != b':' || bytes[16] != b':' {
		return None;
	}
	let year = number(&bytes[0..4])?;
	let month = number(&bytes[5..7])?;
	let day = number(&bytes[8..10])?;
	let hour = number(&bytes[11..13])?;
	let minute = number(&bytes[14..16])?;
	let second = number(&bytes[17..19])?;
	if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
		return None;
	}
	if hour > 23 || minute > 59 || second > 60 {
		return None;
	}
	let mut at = 19;
	let mut nanos: i128 = 0;
	if bytes[at] == b'.' {
		let digits = bytes[at + 1..]
			.iter()
			.take_while(|byte| byte.is_ascii_digit())
			.count();
		if digits == 0 {
			return None;
		}
		for (place, byte) in bytes[at + 1..at + 1 + digits].iter().take(9).enumerate() {
			nanos += i128::from(byte - b'0') * 10_i128.pow(8 - place as u32);
		}
		at += 1 + digits;
	}
	let offset = match bytes.get(at)? {
		b'Z' if bytes.len() == at + 1 => 0,
		sign @ (b'+' | b'-') if bytes.len() == at + 6 && bytes[at + 3] == b':' => {
			let hours = number(&bytes[at + 1..at + 3])?;
			let minutes = number(&bytes[at + 4..at + 6])?;
			let seconds = hours * 3600 + minutes * 60;
			if *sign == b'+' { seconds } else { -seconds }
		}
		_ => return None,
	};
	let days = days_from_civil(year, month, day);
	let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
	Some(i128::from(seconds) * 1_000_000_000 + nanos)
}

/// The digits of `bytes` as a number, or `None` if any byte is not a digit.
fn number(bytes: &[u8]) -> Option<i64> {
	bytes.iter().try_fold(0_i64, |total, byte| {
		byte.is_ascii_digit()
			.then(|| total * 10 + i64::from(byte - b'0'))
	})
}

/// Days from 1970-01-01 to the given day of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
	let year = if month <= 2 { year - 1 } else { year };
	let era = year.div_euclid(400);
	let year_of_era = year.rem_euclid(400);
	let month_index = (month + 9) % 12;
	let day_of_year = (153 * month_index + 2) / 5 + day - 1;
	let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	era * 146_097 + day_of_era - 719_468
}
