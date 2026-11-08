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
//! retention sweep in `crate::cli::serve::tasks`) and removes files whose name is
//! older than `[storage] delivery_log_days` (30 by default). `0` disables
//! the log entirely: no directory is created and no records are written.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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
	/// The class of the message; absent for `personal` and in every record
	/// written before the field existed.
	#[serde(default, skip_serializing_if = "is_personal")]
	pub class: crate::evidence::MailClass,
}

fn is_personal(class: &crate::evidence::MailClass) -> bool {
	*class == crate::evidence::MailClass::Personal
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

mod lines;
use lines::{Line, MAX_LINE_BYTES, day_in_window, read_capped_line};

mod day;
pub use day::{MAX_LINE, day_name};

mod time;
pub(crate) use time::parse_rfc3339;
use time::{Day, date_for_epoch, days_between, parse_day_filename};
pub use time::{now_epoch, parse_since};

#[cfg(test)]
mod tests;
