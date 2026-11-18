//! Reading the ledger: the cursor that walks the records in UID order, and
//! the lookups it answers without holding the file in memory.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use super::error::corrupt;
use super::file::{Ledger, WORKSPACE};
use super::format::{Fingerprint, HEADER, RECORD, decode};

/// Records the cursor walks over before a lookup gives up and searches.
const NEAR: u32 = 64;

/// Records read ahead at once, which is the workspace charged at open.
const WINDOW_RECORDS: u64 = WORKSPACE as u64 / RECORD;

#[cfg(test)]
thread_local! {
	/// Positional reads of the ledger file by this thread, for the tests.
	pub(super) static READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl Ledger {
	/// The fingerprint held for `uid`, `None` when it is not confirmed. A UID
	/// above the last one confirmed is answered without reading. A UID
	/// above the cursor moves it with a binary search over the records, so a
	/// lookup reads a few records and never the whole file, and a UID that
	/// follows the last one answered is found by walking the records read
	/// ahead, not by searching again; a UID below the
	/// cursor is answered where the cursor already is, so it is one an earlier
	/// call in the same window asked for or one the file does not hold.
	pub(in crate::migrate::imap) fn fingerprint(
		&mut self,
		uid: u32,
	) -> io::Result<Option<Fingerprint>> {
		if self.count == 0 {
			return Ok(None);
		}
		// Nothing above the last confirmed UID is held, which is every UID
		// of a resume, so those answer without touching the file. The cursor
		// ends past the records, as if it had walked there.
		if uid > self.last {
			self.at = self.count;
			self.current = None;
			return Ok(None);
		}
		if !self.current.is_some_and(|(current, _)| current >= uid) {
			// The next UID of a replay is almost always the next record, so
			// walk a few before paying for a binary search.
			let mut past_end = false;
			if self.current.is_some() {
				let mut steps = 0;
				while steps < NEAR && self.current.is_some_and(|(current, _)| current < uid) {
					self.at += 1;
					self.load()?;
					steps += 1;
				}
				past_end = self.current.is_none();
			}
			if !past_end && !self.current.is_some_and(|(current, _)| current >= uid) {
				self.at = self.lower_bound(uid)?;
				self.load()?;
			}
		}
		Ok(self
			.current
			.as_ref()
			.filter(|(current, _)| *current == uid)
			.map(|(_, fingerprint)| *fingerprint))
	}

	/// Read the record the cursor is on, unless it is past the end.
	pub(super) fn load(&mut self) -> io::Result<()> {
		self.current = if self.at < self.count {
			Some(self.ahead(self.at)?)
		} else {
			None
		};
		Ok(())
	}

	/// The index of the first record whose UID is at least `uid`.
	pub(super) fn lower_bound(&mut self, uid: u32) -> io::Result<u64> {
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

	/// Where record `index` starts.
	pub(super) fn offset(index: u64) -> io::Result<u64> {
		index
			.checked_mul(RECORD)
			.and_then(|offset| offset.checked_add(HEADER))
			.ok_or_else(|| io::Error::other("invalid migration ledger offset"))
	}

	/// One positional read of the file, a short file being a corrupt one.
	pub(super) fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
		#[cfg(test)]
		READS.with(|reads| reads.set(reads.get() + 1));
		self.handle()?
			.read_exact_at(buffer, offset)
			.map_err(|error| match error.kind() {
				io::ErrorKind::UnexpectedEof => {
					corrupt(&self.path, "it is shorter than it was read as")
				}
				_ => error,
			})
	}

	/// The record at `index`, whose checksum must hold.
	pub(super) fn record(&self, index: u64) -> io::Result<(u32, Fingerprint)> {
		let mut bytes = [0u8; RECORD as usize];
		self.read_at(&mut bytes, Self::offset(index)?)?;
		decode(&bytes).map_err(|_| corrupt(&self.path, "a record does not match its checksum"))
	}

	/// The record at `index` out of the read-ahead window, which a read
	/// refills from that record on when the index lies outside it.
	pub(super) fn ahead(&mut self, index: u64) -> io::Result<(u32, Fingerprint)> {
		let held = self.window.len() as u64 / RECORD;
		if index < self.window_from || index >= self.window_from + held {
			let records = (self.count - index).min(WINDOW_RECORDS);
			let mut window = std::mem::take(&mut self.window);
			window.resize((records * RECORD) as usize, 0);
			self.read_at(&mut window, Self::offset(index)?)?;
			self.window = window;
			self.window_from = index;
		}
		let start = ((index - self.window_from) * RECORD) as usize;
		decode(&self.window[start..start + RECORD as usize])
			.map_err(|_| corrupt(&self.path, "a record does not match its checksum"))
	}

	pub(super) fn handle(&self) -> io::Result<&File> {
		self.write
			.as_ref()
			.or(self.read.as_ref())
			.ok_or_else(|| io::Error::other("migration ledger is not open"))
	}
}
