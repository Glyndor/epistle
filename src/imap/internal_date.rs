//! INTERNALDATE (RFC 9051 §2.3.3): the instant a message arrived and the
//! zone it was given in. The APPEND and REPLACE date-time is parsed by
//! `command::date_time`.
//!
//! The instant is the message file's mtime. The zone matters only for
//! messages APPENDed with a date-time: BEFORE, ON and SINCE compare the date
//! as the client wrote it, so a message appended at `25-Mar-2007 00:00:00
//! +0200` is ON 25-Mar-2007 although it is the 24th in UTC. A non-zero zone
//! is kept in a `<id>.zone` sidecar holding minutes east of UTC.

use crate::util::path_component::{MessageExt, message_file, message_tmp_file};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const MONTHS: [&str; 12] = [
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The furthest a zone may be from UTC, in minutes: `+2359`.
pub(crate) const MAX_ZONE: i16 = 24 * 60 - 1;

/// An instant and the zone, in minutes east of UTC, it is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalDate {
	/// The instant.
	pub time: SystemTime,
	/// Minutes east of UTC.
	pub zone: i16,
}

/// `time` as an RFC 9051 `date-time` in `zone`, without quotes.
pub(crate) fn format(time: SystemTime, zone: i16) -> String {
	let local = local_seconds(time, zone);
	let (year, month, day) = civil_from_days(local.div_euclid(86_400));
	let hms = local.rem_euclid(86_400);
	let sign = if zone < 0 { '-' } else { '+' };
	let offset = zone.unsigned_abs();
	format!(
		"{day:2}-{}-{year:04} {:02}:{:02}:{:02} {sign}{:02}{:02}",
		MONTHS[month as usize - 1],
		hms / 3600,
		hms % 3600 / 60,
		hms % 60,
		offset / 60,
		offset % 60,
	)
}

/// Days since the epoch of the date `time` falls on in `zone`.
pub(crate) fn local_day(time: SystemTime, zone: i16) -> i64 {
	local_seconds(time, zone).div_euclid(86_400)
}

fn local_seconds(time: SystemTime, zone: i16) -> i64 {
	let utc = match time.duration_since(UNIX_EPOCH) {
		Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX / 2),
		Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX / 2),
	};
	utc + i64::from(zone) * 60
}

/// The zone recorded for message `id` in `dir`; UTC when there is none.
pub(super) fn read_zone(dir: &Path, id: Uuid) -> i16 {
	message_file(dir, id, MessageExt::Zone)
		.ok()
		.and_then(|path| crate::util::fs_walk::read_to_string(&path).ok())
		.and_then(|text| text.trim().parse::<i16>().ok())
		.filter(|zone| zone.unsigned_abs() <= MAX_ZONE as u16)
		.unwrap_or(0)
}

/// Record a non-zero `zone` for message `id` in `dir`.
pub(super) fn write_zone(dir: &Path, id: Uuid, zone: i16) -> std::io::Result<()> {
	if zone == 0 {
		return Ok(());
	}
	let tmp = message_tmp_file(dir, id, MessageExt::Zone)?;
	std::fs::write(&tmp, zone.to_string())?;
	std::fs::rename(&tmp, message_file(dir, id, MessageExt::Zone)?)
}

/// The proleptic Gregorian date of a day number since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	let year = yoe + era * 400 + i64::from(month <= 2);
	(year, month, day)
}

#[cfg(test)]
#[path = "internal_date_tests.rs"]
mod tests;
