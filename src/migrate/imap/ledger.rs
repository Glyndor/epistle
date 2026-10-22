//! What one remote folder has already handed over, kept next to the progress
//! file so a rerun does not download it again.
//!
//! `<digest>.ledger` holds the UIDVALIDITY its records belong to and one fixed
//! record per confirmed message: its UID, the fingerprint of the identity the
//! deduplication index uses, and a checksum over the two. Records are appended
//! in UID order, so the UIDs of a listing window are answered by a forward scan
//! and nothing is held in memory beyond one record.
//!
//! A run appends the messages of a batch once they are stored and
//! synchronized, and before the checkpoint that confirms that batch, so the
//! file can only be ahead of the progress file and never behind it. A record is
//! therefore never written for a message that is not in the local mailbox.
//!
//! Nothing is written for a source that announces no UIDVALIDITY, because its
//! UIDs carry no identity: those folders are matched against the local mailbox
//! on every run, as before. A source that changes UIDVALIDITY has its ledger
//! discarded with a warning, and the folder is read again from the start.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::state_files;
use super::{ClientError, durability, metadata::Budget};

/// The fingerprint of one message identity.
pub(super) type Fingerprint = [u8; 32];

/// What marks the file as ours, and the version of the record layout.
const MAGIC: &[u8; 8] = b"EPSTLG1\0";

/// Magic, UIDVALIDITY and the record count the file was written with.
const HEADER: u64 = 16;

/// UID, fingerprint and checksum.
const RECORD: u64 = 40;

/// The largest ledger. At 40 octets per record it holds 26 million confirmed
/// messages, far past any mailbox that still has room for them.
const MAX_LEDGER_BYTES: u64 = 1024 * 1024 * 1024;

/// The workspace one folder's ledger is charged when it is opened, like the
/// recovery index: the file is read where it lies, so nothing grows with the
/// number of messages it holds.
const WORKSPACE: usize = 64 * 1024;

/// The confirmed messages of one remote folder, read and appended through
/// descriptors already open on the state directory.
#[derive(Debug)]
pub(super) struct Ledger {
	dir: Option<File>,
	path: PathBuf,
	read: Option<File>,
	write: Option<File>,
	/// Whether records may be appended. A ledger opened to be read, and one for
	/// a source that announces no UIDVALIDITY, hold nothing and add nothing.
	writable: bool,
	uid_validity: u32,
	count: u64,
	last: u32,
	at: u64,
	current: Option<(u32, Fingerprint)>,
}

impl Ledger {
	/// A ledger that confirms nothing.
	fn empty(path: PathBuf, uid_validity: u32) -> Self {
		Ledger {
			dir: None,
			path,
			read: None,
			write: None,
			writable: false,
			uid_validity,
			count: 0,
			last: 0,
			at: 0,
			current: None,
		}
	}

	/// The UIDVALIDITY the records below belong to.
	#[cfg(test)]
	pub(super) fn uid_validity(&self) -> u32 {
		self.uid_validity
	}

	/// How many messages this ledger confirms.
	#[cfg(test)]
	pub(super) fn count(&self) -> u64 {
		self.count
	}

	/// The largest UID it confirms.
	#[cfg(test)]
	pub(super) fn last_uid(&self) -> u32 {
		self.last
	}

	/// The fingerprint held for `uid`, `None` when it is not confirmed. Calls
	/// in ascending UID order walk the file forward; a UID below the current
	/// position seeks to it again.
	pub(super) fn fingerprint(&mut self, uid: u32) -> io::Result<Option<Fingerprint>> {
		if self.count == 0 {
			return Ok(None);
		}
		if !self
			.current
			.as_ref()
			.is_some_and(|(current, _)| *current >= uid)
		{
			self.at = self.lower_bound(uid)?;
			self.load()?;
		}
		while self.current.is_some_and(|(current, _)| current < uid) {
			self.at += 1;
			self.load()?;
		}
		Ok(self
			.current
			.as_ref()
			.filter(|(current, _)| *current == uid)
			.map(|(_, fingerprint)| *fingerprint))
	}

	/// Read the record the cursor is on, unless it is past the end.
	fn load(&mut self) -> io::Result<()> {
		self.current = if self.at < self.count {
			Some(self.record(self.at)?)
		} else {
			None
		};
		Ok(())
	}

	/// The index of the first record whose UID is at least `uid`.
	fn lower_bound(&mut self, uid: u32) -> io::Result<u64> {
		let (mut low, mut high) = (0u64, self.count);
		while low < high {
			let middle = low + (high - low) / 2;
			if self.record(middle)?.0 < uid {
				low = middle + 1;
			} else {
				high = middle;
			}
		}
		Ok(low)
	}

	/// The record at `index`, whose checksum must hold.
	fn record(&self, index: u64) -> io::Result<(u32, Fingerprint)> {
		let offset = index
			.checked_mul(RECORD)
			.and_then(|offset| offset.checked_add(HEADER))
			.ok_or_else(|| io::Error::other("invalid migration ledger offset"))?;
		let mut bytes = [0u8; RECORD as usize];
		self.handle()?
			.read_exact_at(&mut bytes, offset)
			.map_err(|error| match error.kind() {
				io::ErrorKind::UnexpectedEof => {
					corrupt(&self.path, "it is shorter than it was read as")
				}
				_ => error,
			})?;
		let mut fingerprint = [0u8; 32];
		fingerprint.copy_from_slice(&bytes[4..36]);
		let uid = u32::from_le_bytes(bytes[..4].try_into().expect("uid"));
		if u32::from_le_bytes(bytes[36..40].try_into().expect("checksum"))
			!= checksum(uid, &fingerprint)
		{
			return Err(corrupt(&self.path, "a record does not match its checksum"));
		}
		Ok((uid, fingerprint))
	}

	fn handle(&self) -> io::Result<&File> {
		self.write
			.as_ref()
			.or(self.read.as_ref())
			.ok_or_else(|| io::Error::other("migration ledger is not open"))
	}

	/// Check the header and drop a tail record a cut left incomplete. An append
	/// reaches the disk as a prefix of its records, so the division below
	/// already leaves the unfinished one out: it was never confirmed, and the
	/// message behind it is matched against the local mailbox again. The last
	/// whole record must still match its checksum, or the file is corrupt
	/// rather than cut.
	fn prepare(&mut self) -> io::Result<()> {
		let file = self.handle()?.try_clone()?;
		let length = file.metadata()?.len();
		let mut head = [0u8; HEADER as usize];
		if length < HEADER || file.read_exact_at(&mut head, 0).is_err() {
			return Err(corrupt(&self.path, "its header is incomplete"));
		}
		if &head[..8] != MAGIC {
			return Err(corrupt(
				&self.path,
				"it does not start with the migration ledger marker",
			));
		}
		self.uid_validity = u32::from_le_bytes(head[8..12].try_into().expect("uid validity"));
		let count = (length - HEADER) / RECORD;
		if count > 0 {
			self.record(count - 1)?;
		}
		if length != HEADER + count * RECORD {
			self.trim(HEADER + count * RECORD)?;
		}
		self.count = count;
		self.last = if count > 0 {
			self.record(count - 1)?.0
		} else {
			0
		};
		Ok(())
	}

	/// Cut the file back to `length` octets.
	fn trim(&mut self, length: u64) -> io::Result<()> {
		if !self.writable {
			return Ok(());
		}
		let file = self
			.write
			.as_ref()
			.ok_or_else(|| io::Error::other("migration ledger is not open"))?;
		file.set_len(length)?;
		durability::sync(file, "ledger-file")
	}

	/// Record `records` as confirmed. They must arrive in ascending UID order
	/// above everything the file holds, which is what keeps a window lookup to
	/// a forward scan. A ledger that can only be read, and one for a source
	/// that announces no UIDVALIDITY, records nothing: there are no UIDs to name.
	pub(super) fn confirm(&mut self, records: &[(u32, Fingerprint)]) -> io::Result<()> {
		if records.is_empty() || !self.writable {
			return Ok(());
		}
		if records.iter().any(|&(uid, _)| uid <= self.last)
			|| records.windows(2).any(|pair| pair[1].0 <= pair[0].0)
		{
			return Err(io::Error::other(
				"migration ledger records are out of UID order",
			));
		}
		let end = self
			.count
			.checked_add(records.len() as u64)
			.and_then(|count| count.checked_mul(RECORD))
			.and_then(|bytes| bytes.checked_add(HEADER))
			.ok_or_else(|| io::Error::other("migration ledger is too large"))?;
		if end > MAX_LEDGER_BYTES {
			return Err(too_large(&self.path));
		}
		let mut body = Vec::with_capacity(records.len() * RECORD as usize);
		for &(uid, fingerprint) in records {
			body.extend_from_slice(&uid.to_le_bytes());
			body.extend_from_slice(&fingerprint);
			body.extend_from_slice(&checksum(uid, &fingerprint).to_le_bytes());
		}
		let offset = HEADER + self.count * RECORD;
		{
			let file = self.writer()?;
			file.write_all_at(&body, offset)?;
			durability::sync(file, "ledger-file")?;
		}
		self.count += records.len() as u64;
		self.last = records[records.len() - 1].0;
		self.at = self.count;
		self.current = None;
		Ok(())
	}

	/// The descriptor records are appended to, creating the file through an
	/// exclusive temporary and a rename the first time.
	fn writer(&mut self) -> io::Result<&File> {
		if self.write.is_none() {
			let dir = self
				.dir
				.as_ref()
				.ok_or_else(|| io::Error::other("migration ledger is read only"))?;
			if self.read.is_none() {
				state_files::replace(
					dir,
					&self.path,
					&header(self.uid_validity),
					"ledger-file",
					"ledger-directory",
				)?;
			}
			self.write = Some(state_files::appendable(dir, &self.path)?);
		}
		Ok(self.write.as_ref().expect("ledger writer"))
	}

	/// Leave no record of a ledger that belongs to another UIDVALIDITY. The
	/// file stays a ledger that holds nothing, so the next run reads it as an
	/// empty one instead of refusing it.
	fn discard(&mut self) -> io::Result<()> {
		if self.writable {
			state_files::replace(
				self.dir.as_ref().expect("ledger directory"),
				&self.path,
				&header(self.uid_validity),
				"ledger-file",
				"ledger-directory",
			)?;
		}
		self.read = None;
		self.write = None;
		self.count = 0;
		self.last = 0;
		self.at = 0;
		self.current = None;
		Ok(())
	}
}

/// Open the ledger of one folder through the open state directory. Nothing is
/// created and nothing is discarded unless `writable`; a missing file, a
/// missing directory or a source without UIDVALIDITY is a ledger that confirms
/// nothing.
pub(super) fn open(
	root: &File,
	account: &str,
	path: PathBuf,
	uid_validity: u32,
	writable: bool,
) -> io::Result<Ledger> {
	if uid_validity == 0 {
		return Ok(Ledger::empty(path, 0));
	}
	let dir = match state_files::directory(root, account, writable) {
		Ok(dir) => dir,
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			return Ok(Ledger::empty(path, uid_validity));
		}
		Err(error) => return Err(error),
	};
	let read = match state_files::read(&dir, &path) {
		Ok(file) => Some(file),
		Err(error) if error.kind() == io::ErrorKind::NotFound => None,
		Err(error) => return Err(error),
	};
	let write = match (&read, writable) {
		(Some(_), true) => Some(state_files::appendable(&dir, &path)?),
		_ => None,
	};
	let mut ledger = Ledger {
		dir: Some(dir),
		path,
		read,
		write,
		writable,
		uid_validity,
		count: 0,
		last: 0,
		at: 0,
		current: None,
	};
	if ledger.read.is_none() {
		return Ok(ledger);
	}
	ledger.prepare()?;
	if ledger.uid_validity != uid_validity {
		tracing::warn!(
			path = %ledger.path.display(),
			was = ledger.uid_validity,
			now = uid_validity,
			"the source changed UIDVALIDITY: the confirmed messages of this folder are discarded and it is copied again"
		);
		ledger.discard()?;
		ledger.uid_validity = uid_validity;
	}
	Ok(ledger)
}

/// Charge the workspace of one folder's ledger.
pub(super) fn charge(budget: &mut Budget) -> Result<(), ClientError> {
	budget.charge(WORKSPACE)
}

/// The first 32 bits of the SHA-256 over a record, so a torn or altered
/// record is caught instead of read as another message.
fn checksum(uid: u32, fingerprint: &Fingerprint) -> u32 {
	let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
	hash.update(&uid.to_le_bytes());
	hash.update(fingerprint);
	u32::from_le_bytes(
		hash.finish().as_ref()[..4]
			.try_into()
			.expect("SHA-256 prefix"),
	)
}

/// The header bytes of a ledger that holds no records yet.
fn header(uid_validity: u32) -> Vec<u8> {
	let mut bytes = Vec::with_capacity(HEADER as usize);
	bytes.extend_from_slice(MAGIC);
	bytes.extend_from_slice(&uid_validity.to_le_bytes());
	bytes.resize(HEADER as usize, 0);
	bytes
}

/// A ledger that cannot be read stops the folder instead of importing
/// anything: the message names the file and how to start over.
fn corrupt(path: &Path, detail: &str) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} cannot be read, {detail}; nothing was imported and nothing was removed: delete that file to copy this folder again",
			path.display()
		),
	)
}

/// A ledger past its size bound: the same refusal, with the bound named.
fn too_large(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} holds more than {MAX_LEDGER_BYTES} bytes of confirmed messages; nothing was imported and nothing was removed: delete that file to copy this folder again",
			path.display()
		),
	)
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
