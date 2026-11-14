//! The ledger file itself: what it holds, and how records are appended to it.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use super::error::{out_of_order, rewritten, too_large};
use super::format::{Fingerprint, HEADER, MAX_LEDGER_BYTES, RECORD, checksum, header};
use super::{durability, state_files};

/// The workspace one folder's ledger is charged when it is opened, like the
/// recovery index: the file is read where it lies, so nothing grows with the
/// number of messages it holds.
pub(super) const WORKSPACE: usize = 64 * 1024;

/// The confirmed messages of one remote folder, read and appended through
/// descriptors already open on the state directory.
#[derive(Debug)]
pub(in crate::migrate::imap) struct Ledger {
	pub(super) dir: Option<File>,
	pub(super) path: PathBuf,
	pub(super) read: Option<File>,
	pub(super) write: Option<File>,
	/// Whether records may be appended. A ledger opened to be read, and one for
	/// a source that announces no UIDVALIDITY, hold nothing and add nothing.
	pub(super) writable: bool,
	pub(super) uid_validity: u32,
	pub(super) count: u64,
	pub(super) last: u32,
	pub(super) at: u64,
	pub(super) current: Option<(u32, Fingerprint)>,
	/// Records read ahead of the cursor in one positional read, so walking
	/// the file in UID order costs one read per window and not one per record.
	pub(super) window: Vec<u8>,
	pub(super) window_from: u64,
}

impl Ledger {
	/// A ledger that confirms nothing.
	pub(super) fn empty(path: PathBuf, uid_validity: u32) -> Self {
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
			window: Vec::new(),
			window_from: 0,
		}
	}

	/// Record `records` as confirmed. They must arrive in ascending UID order,
	/// which is what lets a lookup find them by binary search. A record at or
	/// below the UID the file already reaches is left out rather than refused:
	/// a folder that has to be replayed from the start confirms messages below
	/// what an earlier batch reached, and refusing them would leave that folder
	/// unable to finish. Such a message is then only matched against the local
	/// mailbox, so deleting it there brings it back on a later replay. A batch
	/// that does not arrive in ascending order is a caller that cannot be
	/// trusted with the file, so it is refused by name. A ledger that can only
	/// be read, and one for a source that announces no UIDVALIDITY, records
	/// nothing: there are no UIDs to name.
	pub(in crate::migrate::imap) fn confirm(
		&mut self,
		records: &[(u32, Fingerprint)],
	) -> io::Result<()> {
		if records.is_empty() || !self.writable {
			return Ok(());
		}
		if records.windows(2).any(|pair| pair[1].0 <= pair[0].0) {
			return Err(out_of_order(&self.path));
		}
		let reached = self.last;
		let records = &records[records.partition_point(|&(uid, _)| uid <= reached)..];
		if records.is_empty() {
			return Ok(());
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
			// The offset comes from the length read when the file was opened,
			// so what the file holds is checked before anything is written over
			// it.
			if file.metadata()?.len() != offset {
				return Err(rewritten(&self.path));
			}
			file.write_all_at(&body, offset)?;
			durability::sync(file, "ledger-file")?;
		}
		self.count += records.len() as u64;
		self.last = records[records.len() - 1].0;
		self.at = self.count;
		self.current = None;
		self.window.clear();
		Ok(())
	}

	/// The descriptor records are appended to, creating the file through an
	/// exclusive temporary and a rename the first time.
	pub(super) fn writer(&mut self) -> io::Result<&File> {
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

	/// Cut the file back to `length` octets.
	pub(super) fn trim(&mut self, length: u64) -> io::Result<()> {
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

	/// Leave no record of a ledger that belongs to another UIDVALIDITY. The
	/// file stays a ledger that holds nothing, so the next run reads it as an
	/// empty one instead of refusing it.
	pub(super) fn discard(&mut self) -> io::Result<()> {
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
		self.window.clear();
		Ok(())
	}
}
