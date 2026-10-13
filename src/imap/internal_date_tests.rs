use super::{format, local_day};
use std::time::{Duration, UNIX_EPOCH};

/// 2007-03-24T22:00:00Z, which is 25-Mar-2007 00:00:00 at +0200.
const INSTANT: u64 = 1_174_773_600;

#[test]
fn the_date_is_shown_in_its_zone() {
	let time = UNIX_EPOCH + Duration::from_secs(INSTANT);
	assert_eq!(format(time, 120), "25-Mar-2007 00:00:00 +0200");
	assert_eq!(format(time, 0), "24-Mar-2007 22:00:00 +0000");
	assert_eq!(format(time, -570), "24-Mar-2007 12:30:00 -0930");
	assert_eq!(format(UNIX_EPOCH, 0), " 1-Jan-1970 00:00:00 +0000");
	let leap = UNIX_EPOCH + Duration::from_secs(1_709_251_199);
	assert_eq!(format(leap, 0), "29-Feb-2024 23:59:59 +0000");
}

#[test]
fn the_local_day_follows_the_zone() {
	let time = UNIX_EPOCH + Duration::from_secs(INSTANT);
	assert_eq!(local_day(time, 120), 13_597);
	assert_eq!(local_day(time, 0), 13_596);
}

#[test]
fn dates_before_the_epoch_keep_their_day() {
	let time = UNIX_EPOCH - Duration::from_secs(3600);
	assert_eq!(format(time, 0), "31-Dec-1969 23:00:00 +0000");
	assert_eq!(local_day(time, 0), -1);
	assert_eq!(local_day(time, 120), 0);
}
