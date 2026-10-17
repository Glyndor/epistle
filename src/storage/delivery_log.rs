//! Per-recipient delivery log, one JSON record per line.
//!
//! Every time a recipient of a queued message reaches an outcome (delivered,
//! deferred, failed permanently, suppressed by the suppression list, or
//! canceled by an operator `queue` action), one record is appended to a
//! daily JSON-lines file under `<data_dir>/deliverylog/`. Records are
//! metadata only: no subject and no body, never the message bytes. Operators
//! and integrators read it back through `epistle delivery list` and
//! `GET /api/v1/deliveries`; both readers stream the files in order and
//! stop at the caller's `--limit`, so a busy server never loads the whole
//! log into memory.
//!
//! Files are written append-only with one `write` per record and created
//! `0600` from the start, the same way `crate::storage::write_secret`
//! creates any other per-recipient metadata file. The file name is always
//! `YYYY-MM-DD.jsonl`, derived from the wall clock date the record was
//! produced, so no caller input ever reaches the path.
//!
//! The sweep runs alongside the other periodic sweeps (the archive
//! retention sweep in `serve_tasks`) and removes files whose name is
//! older than `[storage] delivery_log_days` (30 by default). `0` disables
//! the log entirely: no directory is created and no records are written.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The default retention window when the operator has not configured one:
/// the same 30 days the operator who turned the log on would have asked
/// for, with a positive value so the sweep is a no-op until then.
pub const DEFAULT_DELIVERY_LOG_DAYS: u64 = 30;

/// What happened to one recipient of one queued message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
	/// The remote server accepted the message for this recipient.
	Delivered,
	/// A transient failure that will be retried. Emitted once per
	/// recipient per message for each distinct reply: a retry deferred for
	/// the same reason as the one before writes no record, one deferred for
	/// a new reason does, up to
	/// [`crate::queue::limits::MAX_DEFERRALS_LOGGED`] per recipient.
	Deferred,
	/// Delivery failed permanently (the message expired or the remote
	/// refused it).
	Failed,
	/// A suppression list refused the recipient before any attempt was made.
	Suppressed,
	/// An operator removed the queue entry before this recipient reached
	/// any other outcome.
	Canceled,
}

impl DeliveryOutcome {
	/// The textual form used in filters and in JSON.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Delivered => "delivered",
			Self::Deferred => "deferred",
			Self::Failed => "failed",
			Self::Suppressed => "suppressed",
			Self::Canceled => "canceled",
		}
	}

	/// The outcome a textual filter is asking for, or `None` when the
	/// string is not a known outcome. Unknown values fail closed at the
	/// CLI / API boundary so a typo never silently matches nothing.
	pub fn parse(value: &str) -> Option<Self> {
		match value {
			"delivered" => Some(Self::Delivered),
			"deferred" => Some(Self::Deferred),
			"failed" => Some(Self::Failed),
			"suppressed" => Some(Self::Suppressed),
			"canceled" => Some(Self::Canceled),
			_ => None,
		}
	}
}

/// One record in the delivery log. Serialized as one line of JSON; the
/// on-disk shape is what `/api/v1/deliveries` and `epistle delivery list`
/// read back, so a key removal or rename is a wire change for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRecord {
	/// Wall-clock epoch seconds the record was produced.
	pub time: u64,
	/// Spool id of the message this recipient belongs to.
	pub spool_id: Uuid,
	/// Local account that submitted the message, when known. `None` when
	/// the message was relayed from another server.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub account: Option<String>,
	/// Envelope sender (`MAIL FROM`); empty for the null reverse-path of a
	/// bounce.
	pub from: String,
	/// The recipient this record is about.
	pub recipient: String,
	/// What happened.
	pub outcome: DeliveryOutcome,
	/// The remote host that gave the answer, when one answered. `-` when
	/// no server answered (a local reason, suppression, or a queue cancel).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote: Option<String>,
	/// The first 200 bytes of the remote reply, when there is one. Never
	/// the message body or the subject; just the SMTP reply line the
	/// remote answered with, useful for an integrator that does not have
	/// the spool open.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reply: Option<String>,
	/// Which attempt this record corresponds to, counting from one. `0`
	/// for a record that has no attempt (suppression, cancel).
	pub attempt: u32,
	/// The caller-supplied correlation map, when the API attached one to
	/// the submission. Empty in every record of a message the API did not
	/// tag.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub extra: BTreeMap<String, String>,
}

/// The on-disk delivery log under `<data_dir>/deliverylog/`. A no-op when
/// `retention_days` is `0`: the directory is not created and [`Self::append`]
/// returns success without writing anything.
#[derive(Debug, Clone)]
pub struct DeliveryLog {
	root: PathBuf,
	/// `0` disables the log entirely.
	retention_days: u64,
}

impl DeliveryLog {
	/// Open the delivery log rooted at `<data_dir>/deliverylog`. The
	/// directory is created on first use by [`Self::append`], not here, so
	/// a `0` retention never leaves an empty directory behind.
	pub fn open(data_dir: &Path, retention_days: u64) -> Self {
		Self {
			root: data_dir.join("deliverylog"),
			retention_days,
		}
	}

	/// Whether the log is configured to keep any record. `0` retention
	/// disables it.
	pub fn is_enabled(&self) -> bool {
		self.retention_days > 0
	}

	/// The retention window the operator configured, in days. `0` means
	/// the log is off.
	pub fn retention_days(&self) -> u64 {
		self.retention_days
	}

	/// Append `record` to today's log file. The file is created `0600` on
	/// the first write of the day; subsequent writes reuse it. A no-op
	/// when the log is disabled, so callers can keep the call site the
	/// same regardless of configuration.
	pub fn append(&self, record: &DeliveryRecord) -> std::io::Result<()> {
		if !self.is_enabled() {
			return Ok(());
		}
		let path = self.path_for_day(date_for_epoch(record.time))?;
		if let Some(parent) = path.parent() {
			fs::create_dir_all(parent)?;
		}
		let mut options = OpenOptions::new();
		options.create(true).append(true);
		#[cfg(unix)]
		{
			// `create(true)` does not set a mode on its own; pin the file
			// to 0600 from the start, the way the other per-recipient
			// metadata files (the corpus keys, the account TOTP stores)
			// do. The first writer of the day creates the file with the
			// correct mode; later writers open an existing file and the
			// mode is left alone.
			if !path.exists() {
				options.mode(0o600);
			}
		}
		let mut file = options.open(&path)?;
		let line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
		file.write_all(&line)?;
		file.write_all(b"\n")?;
		file.sync_all()?;
		Ok(())
	}

	/// Drop files older than `retention_days`, measured against today's
	/// date. "Older than `N`" means strictly more than `N` days old, so
	/// `retention_days = 1` keeps today's file and yesterday's, but
	/// nothing older. Safe to call with a `0` retention: every file is
	/// removed and the directory goes with them, so a server that flips
	/// the setting back to `0` does not leave yesterday's files in place.
	pub fn sweep(&self, now_epoch: u64) -> std::io::Result<u64> {
		if !self.root.is_dir() {
			return Ok(0);
		}
		if !self.is_enabled() {
			// Remove every file (the directory itself is recreated only on
			// the next write), then drop the directory if it is empty.
			let mut removed = 0u64;
			for entry in fs::read_dir(&self.root)? {
				let entry = entry?;
				if entry.file_type().is_ok_and(|kind| kind.is_file())
					&& fs::remove_file(entry.path()).is_ok()
				{
					removed += 1;
				}
			}
			let _ = fs::remove_dir(&self.root);
			return Ok(removed);
		}
		let today = date_for_epoch(now_epoch);
		let mut removed = 0u64;
		for entry in fs::read_dir(&self.root)? {
			let entry = entry?;
			let name = match entry.file_name().into_string() {
				Ok(name) => name,
				Err(_) => continue,
			};
			let Some(date) = parse_day_filename(&name) else {
				continue;
			};
			if days_between(date, today) > self.retention_days
				&& fs::remove_file(entry.path()).is_ok()
			{
				removed += 1;
			}
		}
		Ok(removed)
	}

	/// The full path of the JSON-lines file for `day` (`YYYY-MM-DD`).
	fn path_for_day(&self, day: Day) -> std::io::Result<PathBuf> {
		let mut name = String::with_capacity(17);
		write!(&mut name, "{day}.jsonl").expect("writing to String is infallible");
		Ok(self.root.join(name))
	}

	/// Stream records from the log, newest first (today first, then
	/// yesterday, etc.) up to `limit`. Each record is filtered through
	/// `filter`: a return value of `false` drops the record. Streaming
	/// reads one line at a time from each file, so the whole log never
	/// has to fit in memory. A `None` `limit` reads every record (the
	/// caller is then expected to bound the request, the way the
	/// `/api/v1/deliveries` route does).
	///
	/// The scan order (newest day first) is the order an operator wants
	/// when investigating "what just happened to my message", and is the
	/// order the API and CLI both expose. Reading a file is a flat
	/// in-order scan; the iterator does not sort across days, so the
	/// returned list is "newest day, then that day's records in order,
	/// then the next day". A caller that needs a strict per-record
	/// `time` order can sort the result itself; the on-disk encoding
	/// already has the timestamp.
	pub fn list<F>(&self, limit: Option<usize>, filter: F) -> std::io::Result<Vec<DeliveryRecord>>
	where
		F: FnMut(&DeliveryRecord) -> bool,
	{
		self.list_between(limit, (None, None), filter)
	}

	/// [`DeliveryLog::list`] for records whose time lies in `(since, until)`
	/// (epoch seconds, either end open). A file whose day is outside the
	/// window is not opened. `filter` still sees every record of the files
	/// that are, so it decides on the exact second.
	pub fn list_between<F>(
		&self,
		limit: Option<usize>,
		(since, until): (Option<u64>, Option<u64>),
		mut filter: F,
	) -> std::io::Result<Vec<DeliveryRecord>>
	where
		F: FnMut(&DeliveryRecord) -> bool,
	{
		let mut out: Vec<DeliveryRecord> = Vec::new();
		if !self.root.is_dir() {
			return Ok(out);
		}
		let first = since.map(|epoch| date_for_epoch(epoch).to_string());
		let last = until.map(|epoch| date_for_epoch(epoch).to_string());
		// Newest day first. We list the directory and sort the file
		// names descending; the file name is `YYYY-MM-DD.jsonl`, so a
		// plain string sort gives the right order without parsing.
		let mut files: Vec<PathBuf> = Vec::new();
		for entry in fs::read_dir(&self.root)? {
			let entry = entry?;
			let name = match entry.file_name().into_string() {
				Ok(name) => name,
				Err(_) => continue,
			};
			if name.ends_with(".jsonl") && day_in_window(&name, first.as_deref(), last.as_deref()) {
				files.push(entry.path());
			}
		}
		files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
		let mut line = Vec::new();
		'outer: for file in files {
			let mut reader = match fs::File::open(&file) {
				Ok(handle) => std::io::BufReader::with_capacity(64 * 1024, handle),
				Err(error) => {
					tracing::warn!(file = %file.display(), %error, "delivery log file could not be read");
					continue;
				}
			};
			loop {
				match read_capped_line(&mut reader, &mut line, MAX_LINE_BYTES) {
					Ok(Line::End) => break,
					Ok(Line::TooLong) => {
						tracing::warn!(file = %file.display(), "delivery log line over the size limit skipped");
						continue;
					}
					Ok(Line::Read) => {}
					Err(error) => {
						tracing::warn!(file = %file.display(), %error, "delivery log file could not be read");
						break;
					}
				}
				if line.is_empty() {
					continue;
				}
				let record: DeliveryRecord = match serde_json::from_slice(&line) {
					Ok(record) => record,
					Err(error) => {
						tracing::warn!(file = %file.display(), %error, "delivery log line did not parse");
						continue;
					}
				};
				if !filter(&record) {
					continue;
				}
				out.push(record);
				if let Some(cap) = limit
					&& out.len() >= cap
				{
					break 'outer;
				}
			}
		}
		Ok(out)
	}
}

/// `YYYY-MM-DD` for the wall clock at `epoch` (seconds since the Unix
/// epoch). The date is the operator's local date in UTC: the log's file
/// name must be derivable from a single timestamp, and the wall clock
/// timezone of the host is what the operator sees.
fn date_for_epoch(epoch: u64) -> Day {
	let secs = i64::try_from(epoch).unwrap_or(i64::MAX);
	let days = secs.div_euclid(86_400);
	Day::from_unix_days(days)
}

/// One calendar day in UTC, the file name's date. `packed` is the
/// `YYYY-MM-DD` rendering squashed into one integer for cheap comparison;
/// `unix_days` is the same date as days-since-1970 so the sweep can
/// subtract without re-running the civil-from-days conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Day {
	packed: u32,
	unix_days: i64,
}

impl Day {
	/// Build the day that is `days` days after 1970-01-01.
	fn from_unix_days(days: i64) -> Self {
		// Civil-from-days: Howard Hinnant's algorithm, public domain.
		let z = days + 719_468;
		let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
		let doe = (z - era * 146_097) as u64;
		let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
		let y = (yoe as i64) + era * 400;
		let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
		let mp = (5 * doy + 2) / 153;
		let d = doy - (153 * mp + 2) / 5 + 1;
		let m = if mp < 10 { mp + 3 } else { mp - 9 };
		let y = if m <= 2 { y + 1 } else { y };
		Day {
			packed: y as u32 * 10_000 + m as u32 * 100 + d as u32,
			unix_days: days,
		}
	}
}

impl std::fmt::Display for Day {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let y = self.packed / 10_000;
		let m = (self.packed / 100) % 100;
		let d = self.packed % 100;
		write!(formatter, "{y:04}-{m:02}-{d:02}")
	}
}

impl std::str::FromStr for Day {
	type Err = ();
	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let bytes = value.as_bytes();
		if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
			return Err(());
		}
		let y = std::str::from_utf8(&bytes[..4])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		let m = std::str::from_utf8(&bytes[5..7])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		let d = std::str::from_utf8(&bytes[8..10])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
			return Err(());
		}
		let unix_days = days_from_civil(y as i64, m as u64, d as u64);
		Ok(Day {
			packed: y * 10_000 + m * 100 + d,
			unix_days,
		})
	}
}

/// Howard Hinnant's `days_from_civil` (public domain), the inverse of
/// `from_unix_days`. Used to keep the file-name parsing honest: the
/// packed integer is just a rendering, the `unix_days` field is what the
/// sweep subtracts.
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
	let y = if m <= 2 { y - 1 } else { y };
	let era = if y >= 0 { y } else { y - 399 } / 400;
	let yoe = (y - era * 400) as u64;
	let m = m as i64;
	let d = d as i64;
	let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
	era * 146_097 + doe as i64 - 719_468
}

/// Parse the date out of `<date>.jsonl`. `None` for anything that does not
/// look like a record file; a stray text file in the directory is left
/// alone by the sweep.
fn parse_day_filename(name: &str) -> Option<Day> {
	name.strip_suffix(".jsonl")
		.and_then(|stem| stem.parse().ok())
}

/// Whole days from `earlier` to `later`. Saturates to `0` when the order
/// is reversed (which the sweep never asks for, but the function lives
/// on its own).
fn days_between(earlier: Day, later: Day) -> u64 {
	let diff = later.unix_days.saturating_sub(earlier.unix_days);
	u64::try_from(diff).unwrap_or(0)
}

/// The wall-clock epoch second the sweep task and the test harness pass in.
pub fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Parse a `--since` value: either an RFC 3339 timestamp
/// (`2024-01-02T03:04:05Z`, optional fractional seconds) or a duration
/// like `24h` / `7d` / `30m`. Returns the lower-bound epoch second
/// (records with `time >= since` are included) or an error on
/// unparseable input. `None` is returned only for the empty string, the
/// way the CLI / API callers express "no filter".
pub fn parse_since(value: &str, now_epoch: u64) -> Result<Option<u64>, String> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Ok(None);
	}
	if let Some(rest) = trimmed
		.strip_suffix('h')
		.or_else(|| trimmed.strip_suffix('H'))
	{
		return parse_duration_secs(rest, 3600, "h", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('d')
		.or_else(|| trimmed.strip_suffix('D'))
	{
		return parse_duration_secs(rest, 86_400, "d", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('m')
		.or_else(|| trimmed.strip_suffix('M'))
	{
		return parse_duration_secs(rest, 60, "m", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('s')
		.or_else(|| trimmed.strip_suffix('S'))
	{
		return parse_duration_secs(rest, 1, "s", now_epoch);
	}
	parse_rfc3339(trimmed).map(Some)
}

fn parse_duration_secs(
	digits: &str,
	unit_secs: u64,
	unit_label: &str,
	now_epoch: u64,
) -> Result<Option<u64>, String> {
	let amount: u64 = digits
		.parse()
		.map_err(|_| format!("duration {digits}{unit_label} is not a number"))?;
	Ok(Some(
		now_epoch.saturating_sub(amount.saturating_mul(unit_secs)),
	))
}

/// Hand-rolled RFC 3339 parser: `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`.
/// Avoids the `time` crate's `parsing` feature (a new feature flag would
/// mean a Cargo.toml change, and the existing `time` usage in this
/// codebase is `time::unix_now` only). The output is always UTC: an
/// explicit `+HH:MM` offset is subtracted from the wall-clock fields, so
/// a value like `2024-01-02T03:04:05+02:00` becomes `01:04:05 UTC`.
pub(crate) fn parse_rfc3339(value: &str) -> Result<u64, String> {
	let (date, rest) = value
		.split_once('T')
		.ok_or_else(|| format!("since {value:?} is not RFC 3339 (no T separator)"))?;
	let mut date_iter = date.split('-');
	let year: i64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the year"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric year"))?;
	let month: u64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the month"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric month"))?;
	let day: u64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the day"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric day"))?;
	if date_iter.next().is_some() {
		return Err(format!("since {value:?} has too many date parts"));
	}
	// Reject month/day-of-month ranges here. `days_from_civil` accepts any
	// positive day (e.g. 40) and rolls into the next month, but a
	// well-formed RFC 3339 value is a calendar date, not a day-count.
	if !(1..=12).contains(&month) {
		return Err(format!("since {value:?} has a month out of range"));
	}
	if !day::is_calendar_day(year, month, day) {
		return Err(format!("since {value:?} is not a day of the calendar"));
	}
	let (time, offset_seconds) = if let Some(time) = rest.strip_suffix('Z') {
		(time, 0i64)
	} else if let Some((time, offset)) = rest.rsplit_once('+') {
		let secs = parse_offset(offset)?;
		(time, secs)
	} else if let Some((time, offset)) = rest.rsplit_once('-') {
		let secs = parse_offset(offset)?;
		(time, -secs)
	} else {
		(rest, 0i64)
	};
	let mut time_iter = time.split(':');
	let hour: u64 = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the hour"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric hour"))?;
	let minute: u64 = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the minute"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric minute"))?;
	let second_part = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the seconds"))?;
	if time_iter.next().is_some() {
		return Err(format!("since {value:?} has too many time parts"));
	}
	let second: u64 = match second_part.split_once('.') {
		Some((whole, _frac)) => whole
			.parse()
			.map_err(|_| format!("since {value:?} has a non-numeric second"))?,
		None => second_part
			.parse()
			.map_err(|_| format!("since {value:?} has a non-numeric second"))?,
	};
	if hour > 23 {
		return Err(format!("since {value:?} has an hour out of range"));
	}
	if minute > 59 {
		return Err(format!("since {value:?} has a minute out of range"));
	}
	if second > 60 {
		// Leap second tolerance: real producers do not emit `:60`, but
		// `2024-01-02T23:59:60Z` has shown up in the wild, and rejecting
		// it would be a surprise. We accept and let the caller see
		// `23:59:60` as the next minute in practice (no further
		// validation).
	}
	let days = days_from_civil(year, month, day);
	let hh: i64 =
		i64::try_from(hour).map_err(|_| format!("since {value:?} has an out-of-range hour"))?;
	let mm: i64 =
		i64::try_from(minute).map_err(|_| format!("since {value:?} has an out-of-range minute"))?;
	let ss: i64 =
		i64::try_from(second).map_err(|_| format!("since {value:?} has an out-of-range second"))?;
	let local: i64 = days
		.checked_mul(86_400)
		.and_then(|v| v.checked_add(hh * 3600 + mm * 60 + ss))
		.ok_or_else(|| format!("since {value:?} is out of range"))?;
	let utc = local - offset_seconds;
	u64::try_from(utc).map_err(|_| format!("since {value:?} is before the epoch"))
}

/// `±HH:MM`, the offset part of an RFC 3339 timestamp. Always positive
/// (the sign is the caller's problem, since the prefix character is
/// also the prefix of a negative year in the date).
fn parse_offset(offset: &str) -> Result<i64, String> {
	let mut iter = offset.split(':');
	let hours: i64 = iter
		.next()
		.ok_or_else(|| format!("since ... {offset:?} is not an offset"))?
		.parse()
		.map_err(|_| format!("since ... {offset:?} has a non-numeric hour"))?;
	let minutes: i64 = match iter.next() {
		Some(minutes) => minutes
			.parse()
			.map_err(|_| format!("since ... {offset:?} has a non-numeric minute"))?,
		None => 0,
	};
	let seconds = hours * 3600 + minutes * 60;
	if !(0..60).contains(&minutes) || !day::is_clock_offset(seconds) {
		return Err(format!("since ... {offset:?} is not a UTC offset"));
	}
	Ok(seconds)
}

#[path = "delivery_log_lines.rs"]
mod lines;
use lines::{Line, MAX_LINE_BYTES, day_in_window, read_capped_line};

#[path = "delivery_log_day.rs"]
mod day;
pub use day::{MAX_LINE, day_name};

#[cfg(test)]
#[path = "delivery_log_tests.rs"]
mod tests;
