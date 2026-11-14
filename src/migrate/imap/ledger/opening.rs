//! Opening the ledger of one folder: what the file must hold to be trusted,
//! and what it costs the run while it is open.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use super::error::{corrupt, too_large};
use super::file::{Ledger, WORKSPACE};
use super::format::{HEADER, MAGIC, MAX_LEDGER_BYTES, RECORD, decode};
use super::{Budget, ClientError, state_files};

impl Ledger {
	/// The UIDVALIDITY the records below belong to.
	#[cfg(test)]
	pub(in crate::migrate::imap) fn uid_validity(&self) -> u32 {
		self.uid_validity
	}

	/// How many messages this ledger confirms.
	#[cfg(test)]
	pub(in crate::migrate::imap) fn count(&self) -> u64 {
		self.count
	}

	/// The largest UID it confirms.
	#[cfg(test)]
	pub(in crate::migrate::imap) fn last_uid(&self) -> u32 {
		self.last
	}

	/// Check the header and drop a tail record a cut left incomplete. An append
	/// reaches the disk as a prefix of its records, so the division below
	/// already leaves the unfinished one out: it was never confirmed, and the
	/// message behind it is matched against the local mailbox again. The last
	/// whole record must still match its checksum, or the file is corrupt
	/// rather than cut.
	pub(super) fn prepare(&mut self) -> io::Result<()> {
		let file = self.handle()?.try_clone()?;
		let length = file.metadata()?.len();
		// Nothing here appends past the bound, and the whole file is read
		// next, so a larger one is refused before that read starts.
		if length > MAX_LEDGER_BYTES {
			return Err(too_large(&self.path));
		}
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

	/// Read the whole file once, in a fixed workspace, checking every checksum
	/// and that its UIDs rise strictly. Records are only ever appended in UID
	/// order, so a file whose records repeat or go backwards was not written by
	/// this code: answering from it would silently skip messages or claim
	/// messages that are not stored.
	pub(super) fn verify(&mut self) -> io::Result<()> {
		if self.count == 0 {
			return Ok(());
		}
		let file = self.handle()?;
		let chunk = WORKSPACE / RECORD as usize * RECORD as usize;
		let mut buffer = vec![0u8; chunk];
		let mut previous = None;
		let mut offset = HEADER;
		let mut left = self.count * RECORD;
		while left > 0 {
			let take = (left as usize).min(chunk);
			file.read_exact_at(&mut buffer[..take], offset)
				.map_err(|error| match error.kind() {
					io::ErrorKind::UnexpectedEof => {
						corrupt(&self.path, "it is shorter than it was read as")
					}
					_ => error,
				})?;
			for at in (0..take).step_by(RECORD as usize) {
				let (uid, _) = decode(&buffer[at..at + RECORD as usize])
					.map_err(|_| corrupt(&self.path, "a record does not match its checksum"))?;
				if previous.is_some_and(|last| uid <= last) {
					return Err(corrupt(&self.path, "its records are not in UID order"));
				}
				previous = Some(uid);
			}
			offset += take as u64;
			left -= take as u64;
		}
		Ok(())
	}
}

/// Open the ledger of one folder through the open state directory. Nothing is
/// created and nothing is discarded unless `writable`; a missing file, a
/// missing directory or a source without UIDVALIDITY is a ledger that confirms
/// nothing.
pub(in crate::migrate::imap) fn open(
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
		window: Vec::new(),
		window_from: 0,
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
	// Once the records are known to belong to this UIDVALIDITY, read them all:
	// a discarded ledger holds nothing and there is nothing to check.
	ledger.verify()?;
	Ok(ledger)
}

/// Charge the workspace of one folder's ledger.
pub(in crate::migrate::imap) fn charge(budget: &mut Budget) -> Result<(), ClientError> {
	budget.charge_transient(WORKSPACE)
}
