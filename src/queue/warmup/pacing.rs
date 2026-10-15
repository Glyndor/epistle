//! Spreading a daily cap across the day.
//!
//! A cap of 50 a day is not 50 messages at midnight: the units of the cap
//! come at an even pace, one every `24 h / cap`, with a small burst of an
//! hour's share so a short lull does not waste the next few. This is the
//! generic cell rate algorithm: the group keeps one number, the theoretical
//! arrival time of its next unit, and a unit may go once that time is less
//! than one burst ahead of now. An idle group therefore never builds up more
//! than the burst, whatever the hour.

/// Milliseconds in a day.
pub const DAY_MS: u64 = 86_400_000;

/// The time between two units of a cap of `cap` a day.
pub fn interval_ms(cap: u32) -> u64 {
	DAY_MS / u64::from(cap.max(1))
}

/// How many units may go back to back: an hour's share of the cap, at
/// least one.
pub fn burst(cap: u32) -> u32 {
	cap.max(1).div_ceil(24)
}

/// How far ahead of now the theoretical arrival time may run.
fn tolerance_ms(cap: u32) -> u64 {
	u64::from(burst(cap) - 1) * interval_ms(cap)
}

/// The arrival time `tat_ms` no further ahead of `now_ms` than taking a
/// whole burst can put it. Only a clock set back leaves it further: the
/// wait it would cause is cut to one unit instead of the jump.
pub fn bounded(cap: u32, tat_ms: u64, now_ms: u64) -> u64 {
	let furthest = now_ms
		.saturating_add(tolerance_ms(cap))
		.saturating_add(interval_ms(cap));
	tat_ms.min(furthest)
}

/// Take up to `wanted` units at `now_ms`, when the theoretical arrival time
/// is `tat_ms`. Returns how many may go now and the new arrival time.
pub fn take(cap: u32, tat_ms: u64, now_ms: u64, wanted: u32) -> (u32, u64) {
	let interval = interval_ms(cap);
	let limit = now_ms.saturating_add(tolerance_ms(cap));
	let mut tat = bounded(cap, tat_ms, now_ms).max(now_ms);
	let mut taken = 0;
	while taken < wanted && tat <= limit {
		tat = tat.saturating_add(interval);
		taken += 1;
	}
	(taken, if taken == 0 { tat_ms } else { tat })
}

/// Give back `count` units taken earlier and never used.
pub fn give_back(cap: u32, tat_ms: u64, count: u32) -> u64 {
	tat_ms.saturating_sub(interval_ms(cap).saturating_mul(u64::from(count)))
}

/// The earliest time, at or after `now_ms`, at which one unit may go.
pub fn next_ms(cap: u32, tat_ms: u64, now_ms: u64) -> u64 {
	bounded(cap, tat_ms, now_ms)
		.saturating_sub(tolerance_ms(cap))
		.max(now_ms)
}

#[cfg(test)]
#[path = "pacing_tests.rs"]
mod tests;
