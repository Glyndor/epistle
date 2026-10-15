#[derive(Clone, Copy)]
pub(in crate::cli) enum Unit {
	Size,
	/// Bytes per second, with the same K/M/G/T suffixes as a size.
	Rate,
	Duration,
	Count,
}

pub(in crate::cli) fn parse_value(input: &str, unit: Unit, max: u64) -> Result<u64, &'static str> {
	const INVALID: &str =
		"expected a non-negative integer with a supported suffix within the field range";
	let digit_end = input
		.find(|character: char| !character.is_ascii_digit())
		.unwrap_or(input.len());
	let (digits, suffix) = input.split_at(digit_end);
	let multiplier = match (unit, suffix) {
		(_, "") | (Unit::Duration, "s") => 1,
		(Unit::Size | Unit::Rate, "k" | "K") => 1024,
		(Unit::Size | Unit::Rate, "m" | "M") => 1024_u64.pow(2),
		(Unit::Size | Unit::Rate, "g" | "G") => 1024_u64.pow(3),
		(Unit::Size | Unit::Rate, "t" | "T") => 1024_u64.pow(4),
		(Unit::Duration, "m") => 60,
		(Unit::Duration, "h") => 3600,
		(Unit::Duration, "d") => 86400,
		(Unit::Duration, "w") => 7 * 86400,
		_ => return Err(INVALID),
	};
	digits
		.parse::<u64>()
		.ok()
		.and_then(|value| value.checked_mul(multiplier))
		.filter(|value| *value <= max)
		.ok_or(INVALID)
}
