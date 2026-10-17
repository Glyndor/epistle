//! The append-only, hash-chained evidence log.
//!
//! Records go to `<evidence>/chain/YYYY-MM-DD.jsonl` for the UTC day of the
//! record, one line each. Every file is created `0600` inside a `0700`
//! directory, opened `O_APPEND`, and every record is written with one
//! `write` and `fdatasync`ed before [`Chain::append`] returns, so a record
//! the caller was told about survives a crash.
//!
//! The server and the CLI may both append (a setting change is recorded by
//! the CLI). Every append holds an exclusive `flock` on `chain/.lock` and
//! reads the hash of the last line on disk under it, so two writers never
//! fork the chain. The last line is read by seeking back from the end of the
//! file, never by reading the day.
//!
//! A last line with no newline is a write that was interrupted before it
//! was synced, so no caller was ever told it existed. The writer cuts it off
//! before appending; a verifier reports it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use super::day::Day;
use super::record::{Entry, FORMAT_VERSION, MAX_LINE, Position, Record, sha256, to_hex};
use super::timeref::TimeRef;

/// The name of the directory holding the day files, under the evidence root.
pub const CHAIN_DIR: &str = "chain";

/// A failure after the record may already be on disk: it was written, and
/// what followed (the directory's sync, the head) failed, or the line could
/// not be cut off after a failed write. Whoever holds something that goes
/// with the record (a kept message) must not destroy it on this.
#[derive(Debug)]
pub struct Unconfirmed(std::io::Error);

impl Unconfirmed {
	fn wrap(error: std::io::Error) -> std::io::Error {
		std::io::Error::new(error.kind(), Unconfirmed(error))
	}

	/// Whether `error` is one of these.
	pub fn is(error: &std::io::Error) -> bool {
		error
			.get_ref()
			.is_some_and(|inner| inner.downcast_ref::<Unconfirmed>().is_some())
	}
}

impl std::fmt::Display for Unconfirmed {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			formatter,
			"the record may have been written, but it was not confirmed: {}",
			self.0
		)
	}
}

impl std::error::Error for Unconfirmed {}

/// The writer of the evidence chain.
#[derive(Debug)]
pub struct Chain {
	dir: PathBuf,
	/// Serialises appends inside this process; the `flock` covers others.
	local: Mutex<()>,
	/// What time it is: the wall clock, cross-checked.
	time: Arc<TimeRef>,
}

impl Chain {
	/// Open the chain under `evidence_root`, creating its directory `0700`.
	/// The time reference starts from the newest record the log holds.
	pub fn open(evidence_root: &Path) -> std::io::Result<Self> {
		Self::open_at(evidence_root, crate::storage::delivery_log::now_epoch())
	}

	/// [`Chain::open`] for a process that read the wall clock as `wall`.
	pub fn open_at(evidence_root: &Path, wall: u64) -> std::io::Result<Self> {
		let dir = evidence_root.join(CHAIN_DIR);
		create_private_dir(&dir)?;
		let mut chain = Chain {
			dir,
			local: Mutex::new(()),
			time: Arc::new(TimeRef::new(0)),
		};
		chain.time = Arc::new(chain.start_reference(evidence_root));
		chain.confirm_from_running_server(evidence_root, wall);
		Ok(chain)
	}

	/// A process with no history of its own (every command) believes the
	/// machine's clock only within a margin of the newest record. Past it, the
	/// word of a server that is running will do: its lock is held, and its
	/// last tick says what time it believed. A status file with no live
	/// server behind it, however recent, says nothing. The server's own start
	/// takes the lock after this, so it never believes itself.
	fn confirm_from_running_server(&self, evidence_root: &Path, wall: u64) {
		const AGREE_SECS: u64 = 900;
		if !server_alive(evidence_root) {
			return;
		}
		let Ok(Some(status)) = super::tasks::last_status(evidence_root) else {
			return;
		};
		if status.clock_sound && status.time.abs_diff(wall) <= AGREE_SECS {
			self.time.vouch(wall, std::time::Instant::now());
		}
	}

	/// What is known to have happened, from the head and the newest record.
	/// A log that has nothing is new; one that cannot be read is not
	/// "nothing": it starts believing no clock at all.
	fn start_reference(&self, evidence_root: &Path) -> TimeRef {
		let head = super::head::load(evidence_root).map(|head| head.map(|head| head.time));
		let newest = self.newest_time();
		match (head, newest) {
			(Ok(head), Ok(newest)) => TimeRef::new(head.max(newest).unwrap_or(0)),
			(Err(_), Ok(Some(newest))) => TimeRef::new(newest),
			(Ok(Some(head)), Err(_)) => TimeRef::new(head),
			(head, newest) => {
				tracing::error!(
					head = ?head.err().map(|error| error.kind()),
					chain = ?newest.err().map(|error| error.kind()),
					"the evidence log cannot be read to learn the time of its newest record; \
					 no clock is believed until a timestamp authority or the operator confirms the date"
				);
				TimeRef::unknown()
			}
		}
	}

	/// The time of the newest record on disk: the last one of the newest day
	/// file that has any, else the purge anchor's.
	fn newest_time(&self) -> std::io::Result<Option<u64>> {
		for day in self.days_newest_first(Day(i64::MAX))? {
			if let Some(position) = last_position(&self.day_file(day), false)? {
				return Ok(Some(position.time));
			}
		}
		Ok(super::anchor::read(&self.dir)?.map(|position| position.time))
	}

	/// The time reference every record is stamped from, shared with whatever
	/// else must not trust the wall clock raw.
	pub fn time(&self) -> Arc<TimeRef> {
		Arc::clone(&self.time)
	}

	/// The directory of the day files.
	pub fn dir(&self) -> &Path {
		&self.dir
	}

	/// The file of `day`.
	pub fn day_file(&self, day: Day) -> PathBuf {
		day_file(&self.dir, day)
	}

	/// Append one record for `entry`, stamped with the clock read under the
	/// chain lock, and return the hash of its line. The record is on disk and
	/// synced when this returns `Ok`; on `Err` nothing was appended.
	///
	/// Reading the clock under the lock is what makes sealing a day safe: a
	/// checkpoint is computed under the same lock, so no record can be
	/// stamped before midnight and land after its day was sealed.
	///
	/// The time is [`TimeRef`]'s: the machine's clock when it agrees with
	/// the monotonic clock and with the newest record, else the best
	/// estimate. A clock that jumped never dates a record in the future, and
	/// one that fell behind the newest record never refuses it: the record
	/// takes the time of the one before.
	pub fn append(&self, entry: Entry) -> std::io::Result<[u8; 32]> {
		self.append_with(|| Ok(self.time.read().time), entry)
	}

	/// [`Chain::append`] with the readings of both clocks given, for tests.
	#[cfg(test)]
	pub(crate) fn append_clocked(
		&self,
		wall: u64,
		monotonic: std::time::Instant,
		entry: Entry,
	) -> std::io::Result<[u8; 32]> {
		self.append_with(|| Ok(self.time.read_at(wall, monotonic).time), entry)
	}

	/// [`Chain::append`] at a fixed `time` (never earlier than the last
	/// record): for the sweeper, which runs in the same task as the sealing,
	/// and for tests.
	pub(crate) fn append_at(&self, time: u64, entry: Entry) -> std::io::Result<[u8; 32]> {
		self.append_with(|| Ok(time), entry)
	}

	/// Run `work` holding the chain lock, so no record is appended meanwhile.
	pub fn locked<T>(&self, work: impl FnOnce() -> T) -> std::io::Result<T> {
		let _local = self
			.local
			.lock()
			.map_err(|_| std::io::Error::other("evidence chain lock poisoned"))?;
		let lock = self.lock_file()?;
		lock.lock()?;
		Ok(work())
	}

	fn append_with(
		&self,
		clock: impl FnOnce() -> std::io::Result<u64>,
		entry: Entry,
	) -> std::io::Result<[u8; 32]> {
		let _local = self
			.local
			.lock()
			.map_err(|_| std::io::Error::other("evidence chain lock poisoned"))?;
		let lock = self.lock_file()?;
		lock.lock()?;
		let now = clock()?;
		let last = self.last_position_before_append(Day::of_epoch(now))?;
		// Times never go backwards in the chain: a clock behind the newest
		// record takes its time.
		let time = now.max(last.time);
		let sealed = Day::of_epoch(time);
		if let Some(root) = self.dir.parent()
			&& super::checkpoint::files(root, sealed).json.exists()
		{
			tracing::error!(day = %sealed.name(), "the clock went back into a sealed day; evidence is not written");
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!(
					"the record would fall in {}, a day that is already sealed: the clock went back",
					sealed.name()
				),
			));
		}
		let path = self.day_file(Day::of_epoch(time));
		let record = Record {
			v: FORMAT_VERSION,
			seq: last.seq + 1,
			prev: to_hex(&last.hash),
			time,
			entry,
		};
		let mut line = record.to_line()?;
		let hash = sha256(&line);
		line.push(b'\n');
		let created = !path.exists();
		let mut file = append_file(&path)?;
		let length = file.seek(SeekFrom::End(0))?;
		if let Err(error) = file.write_all(&line).and_then(|()| file.sync_data()) {
			// Never leave a partial line behind a failure we report. If the
			// line cannot be cut off, it may be on disk: the failure is not
			// one that says nothing was written.
			return Err(match file.set_len(length) {
				Ok(()) => error,
				Err(_) => Unconfirmed::wrap(error),
			});
		}
		// From here the record is durable: a failure says so.
		if created {
			File::open(&self.dir)
				.and_then(|dir| dir.sync_all())
				.map_err(Unconfirmed::wrap)?;
		}
		// The head lives outside the evidence directory, so restoring an
		// older copy of the directory is visible to `verify`.
		if let Some(root) = self.dir.parent() {
			super::head::write(root, time, &hash).map_err(Unconfirmed::wrap)?;
		}
		self.time.raise_floor(time);
		Ok(hash)
	}

	/// Where the chain stands: the last record of the newest day file up to
	/// `day` (any later file is newer still, so it is looked at first), or
	/// the purge anchor, or the start.
	fn last_position_before_append(&self, day: Day) -> std::io::Result<Position> {
		let mut days = self.days()?;
		days.retain(|candidate| *candidate >= day);
		if let Some(later) = days.last()
			&& let Some(position) = last_position(&self.day_file(*later), true)?
		{
			return Ok(position);
		}
		for candidate in self.days_newest_first(day)? {
			if let Some(position) = last_position(&self.day_file(candidate), true)? {
				return Ok(position);
			}
		}
		Ok(super::anchor::read(&self.dir)?.unwrap_or(Position::START))
	}

	/// The days that have a file, newest first, none after `until`.
	pub fn days_newest_first(&self, until: Day) -> std::io::Result<Vec<Day>> {
		let mut days = self.days()?;
		days.retain(|day| *day <= until);
		days.reverse();
		Ok(days)
	}

	/// Every day that has a file, oldest first.
	pub fn days(&self) -> std::io::Result<Vec<Day>> {
		let mut days = Vec::new();
		for entry in fs::read_dir(&self.dir)? {
			let entry = entry?;
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			let name = entry.file_name();
			let Some(day) = name
				.to_str()
				.and_then(|name| name.strip_suffix(".jsonl"))
				.and_then(Day::parse)
			else {
				continue;
			};
			days.push(day);
		}
		days.sort();
		Ok(days)
	}

	fn lock_file(&self) -> std::io::Result<File> {
		let mut options = OpenOptions::new();
		options.create(true).truncate(false).write(true);
		#[cfg(unix)]
		options.mode(0o600);
		options.open(self.dir.join(".lock"))
	}
}

/// The name of the file a running server holds locked.
pub const SERVER_LOCK: &str = "server.lock";

/// Take the lock that says a server is running on `evidence_root`, held for as
/// long as the returned file is kept.
pub fn hold_server_lock(evidence_root: &Path) -> std::io::Result<File> {
	create_private_dir(evidence_root)?;
	let mut options = OpenOptions::new();
	options.create(true).truncate(false).write(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	let file = options.open(evidence_root.join(SERVER_LOCK))?;
	file.try_lock().map_err(|error| match error {
		std::fs::TryLockError::WouldBlock => {
			std::io::Error::other("another server holds this evidence directory")
		}
		std::fs::TryLockError::Error(error) => error,
	})?;
	Ok(file)
}

/// Whether some process holds the server lock of `evidence_root` right now.
pub fn server_alive(evidence_root: &Path) -> bool {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW);
	let Ok(file) = options.open(evidence_root.join(SERVER_LOCK)) else {
		return false;
	};
	matches!(
		file.try_lock_shared(),
		Err(std::fs::TryLockError::WouldBlock)
	)
}

/// The file of `day` under the chain directory `dir`.
pub fn day_file(dir: &Path, day: Day) -> PathBuf {
	dir.join(format!("{}.jsonl", day.name()))
}

/// Create `dir` (and missing parents) owner-only.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
	let mut builder = fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	builder.mode(0o700);
	builder.create(dir)
}

fn append_file(path: &Path) -> std::io::Result<File> {
	let mut options = OpenOptions::new();
	options.create(true).append(true).read(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	options.open(path)
}

/// Open a day file for reading without following a link in its last
/// component: a day file replaced by a symlink is refused, not read.
pub fn open_day(path: &Path) -> std::io::Result<File> {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW);
	options.open(path)
}

/// Where the last complete record of `path` leaves the chain, `None` for a
/// missing or empty file. A last record that is not canonical is an error:
/// nothing is appended onto a tail that cannot be read.
pub fn last_position(path: &Path, repair: bool) -> std::io::Result<Option<Position>> {
	let Some(line) = last_line(path, repair)? else {
		return Ok(None);
	};
	let record = Record::parse_canonical(&line).map_err(|why| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!("evidence chain: the last record does not parse ({why})"),
		)
	})?;
	Ok(Some(record.position(&line)))
}

/// The hash of the last complete line of `path`, `None` for a missing or
/// empty file; with `repair`, an interrupted last line is cut off first.
pub fn last_line_hash(path: &Path, repair: bool) -> std::io::Result<Option<[u8; 32]>> {
	Ok(last_line(path, repair)?.map(|line| sha256(&line)))
}

/// The last complete line of `path`, `None` for a missing or empty file. With `repair`, a torn last line (no newline) is cut off
/// first; without it, the hash is that of the last complete line. The file
/// is read backwards a chunk at a time, so the cost is that of the last
/// line, not of the day.
fn last_line(path: &Path, repair: bool) -> std::io::Result<Option<Vec<u8>>> {
	const CHUNK: u64 = 8 * 1024;
	let mut options = OpenOptions::new();
	options.read(true).write(repair);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW);
	let mut file = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	let length = file.metadata()?.len();
	let mut position = length;
	let mut tail: Vec<u8> = Vec::new();
	loop {
		if let Some(end) = tail.iter().rposition(|byte| *byte == b'\n') {
			let start = tail[..end].iter().rposition(|byte| *byte == b'\n');
			if start.is_some() || position == 0 {
				if end + 1 != tail.len() && repair {
					tracing::warn!("evidence chain: cutting off an interrupted last record");
					file.set_len(position + end as u64 + 1)?;
					file.sync_data()?;
				}
				let first = start.map_or(0, |at| at + 1);
				return Ok(Some(tail[first..end].to_vec()));
			}
		} else if position == 0 {
			if length > 0 && repair {
				tracing::warn!("evidence chain: cutting off an interrupted first record");
				file.set_len(0)?;
				file.sync_data()?;
			}
			return Ok(None);
		}
		// A torn line and a complete one, each at most a record long.
		if length - position > 2 * (MAX_LINE as u64 + 1) {
			return Err(oversized());
		}
		let step = CHUNK.min(position);
		position -= step;
		let mut chunk = vec![0u8; step as usize];
		file.seek(SeekFrom::Start(position))?;
		file.read_exact(&mut chunk)?;
		chunk.extend_from_slice(&tail);
		tail = chunk;
	}
}

fn oversized() -> std::io::Error {
	std::io::Error::new(
		std::io::ErrorKind::InvalidData,
		"evidence chain: last record is longer than any record this server writes",
	)
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "chain_tests_clock.rs"]
mod tests_clock;

/// Lines in `day`'s file, for tests.
#[cfg(test)]
pub(super) fn tests_lines(chain: &Chain, day: Day) -> usize {
	std::fs::read_to_string(chain.day_file(day))
		.map(|text| text.lines().count())
		.unwrap_or(0)
}
