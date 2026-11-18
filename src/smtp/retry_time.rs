//! The time a refusal tells a sender to retry at. SMTP has no `Retry-After`,
//! so the time goes in the text, in UTC and to the minute.

/// `HH:MM UTC` of the first whole minute at or after `epoch_secs`: a
/// sender that waits until then is never early.
pub(crate) fn clock_at(epoch_secs: u64) -> String {
	let minutes = epoch_secs.div_ceil(60);
	let of_day = minutes % (24 * 60);
	format!("{:02}:{:02} UTC", of_day / 60, of_day % 60)
}

#[cfg(test)]
mod tests {
	use super::clock_at;

	#[test]
	fn a_whole_minute_is_itself() {
		// 2026-11-15 14:05:00 UTC.
		assert_eq!(clock_at(1_794_405_900), "14:05 UTC");
	}

	#[test]
	fn a_partial_minute_rounds_up_so_the_sender_is_never_early() {
		assert_eq!(clock_at(1_794_405_901), "14:06 UTC");
		assert_eq!(clock_at(1_794_405_959), "14:06 UTC");
	}

	#[test]
	fn midnight_wraps_the_day() {
		assert_eq!(clock_at(86_399), "00:00 UTC");
		assert_eq!(clock_at(0), "00:00 UTC");
	}
}
