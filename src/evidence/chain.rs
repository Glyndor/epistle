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
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use super::day::Day;
use super::record::{Entry, FORMAT_VERSION, GENESIS, MAX_LINE, Record, sha256, to_hex};

/// The name of the directory holding the day files, under the evidence root.
pub const CHAIN_DIR: &str = "chain";

/// The writer of the evidence chain.
#[derive(Debug)]
pub struct Chain {
	dir: PathBuf,
	/// Serialises appends inside this process; the `flock` covers others.
	local: Mutex<()>,
}

impl Chain {
	/// Open the chain under `evidence_root`, creating its directory `0700`.
	pub fn open(evidence_root: &Path) -> std::io::Result<Self> {
		let dir = evidence_root.join(CHAIN_DIR);
		create_private_dir(&dir)?;
		Ok(Chain {
			dir,
			local: Mutex::new(()),
		})
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
	pub fn append(&self, entry: Entry) -> std::io::Result<[u8; 32]> {
		self.append_with(crate::storage::delivery_log::now_epoch, entry)
	}

	/// [`Chain::append`] at a fixed `time`, for tests and replays.
	pub(crate) fn append_at(&self, time: u64, entry: Entry) -> std::io::Result<[u8; 32]> {
		self.append_with(|| time, entry)
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

	fn append_with(&self, clock: impl FnOnce() -> u64, entry: Entry) -> std::io::Result<[u8; 32]> {
		let _local = self
			.local
			.lock()
			.map_err(|_| std::io::Error::other("evidence chain lock poisoned"))?;
		let lock = self.lock_file()?;
		lock.lock()?;
		let time = clock();
		let day = Day::of_epoch(time);
		let path = self.day_file(day);
		let prev = self.last_hash_before_append(day)?;
		let record = Record {
			v: FORMAT_VERSION,
			prev: to_hex(&prev),
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
			// Never leave a partial line behind a failure we report.
			let _ = file.set_len(length);
			return Err(error);
		}
		if created {
			File::open(&self.dir).and_then(|dir| dir.sync_all())?;
		}
		// The head lives outside the evidence directory, so restoring an
		// older copy of the directory is visible to `verify`.
		if let Some(root) = self.dir.parent() {
			super::head::write(root, time, &hash)?;
		}
		Ok(hash)
	}

	/// The hash the next record must carry as `prev`: the last line of the
	/// newest day file up to `day`, or the purge anchor, or [`GENESIS`].
	fn last_hash_before_append(&self, day: Day) -> std::io::Result<[u8; 32]> {
		// Nearly every append lands on a day that already has records.
		if let Some(hash) = last_line_hash(&self.day_file(day), true)? {
			return Ok(hash);
		}
		for candidate in self.days_newest_first(day)? {
			let path = self.day_file(candidate);
			if let Some(hash) = last_line_hash(&path, true)? {
				return Ok(hash);
			}
		}
		Ok(super::anchor::read(&self.dir)?.unwrap_or(GENESIS))
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
	options.mode(0o600);
	options.open(path)
}

/// The hash of the last complete line of `path`, `None` for a missing or
/// empty file. With `repair`, a torn last line (no newline) is cut off
/// first; without it, the hash is that of the last complete line. The file
/// is read backwards a chunk at a time, so the cost is that of the last
/// line, not of the day.
pub fn last_line_hash(path: &Path, repair: bool) -> std::io::Result<Option<[u8; 32]>> {
	const CHUNK: u64 = 8 * 1024;
	let mut file = match OpenOptions::new().read(true).write(repair).open(path) {
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
				return Ok(Some(sha256(&tail[first..end])));
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
