//! A private, disposable identity table with constant process memory.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::Key;

/// Bucket heads and linked records live in one unlinked scratch file.
#[derive(Debug)]
pub(super) struct Table {
	file: File,
	buckets: u64,
	entries: u64,
}

impl Table {
	pub(super) fn new(file: File, entries: u64) -> io::Result<Self> {
		let buckets = entries
			.checked_mul(2)
			.and_then(u64::checked_next_power_of_two)
			.ok_or_else(|| io::Error::other("recovery index is too large"))?
			.max(1);
		let bytes = buckets
			.checked_mul(8)
			.ok_or_else(|| io::Error::other("recovery index is too large"))?;
		file.set_len(bytes)?;
		Ok(Self {
			file,
			buckets,
			entries: 0,
		})
	}

	fn digest(key: &Key) -> [u8; 32] {
		let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
		let size = match key {
			Key::MessageId(id, size) => {
				hash.update(b"id");
				hash.update(id);
				*size
			}
			Key::Digest(bytes, size) => {
				hash.update(b"digest");
				hash.update(bytes);
				*size
			}
		};
		hash.update(&(size as u64).to_le_bytes());
		hash.finish().as_ref().try_into().expect("SHA-256 length")
	}

	fn bucket(&self, hash: &[u8; 32]) -> u64 {
		(u64::from_le_bytes(hash[..8].try_into().expect("prefix")) & (self.buckets - 1)) * 8
	}

	fn offset(&self, entry: u64) -> io::Result<u64> {
		entry
			.checked_sub(1)
			.and_then(|n| n.checked_mul(40))
			.and_then(|n| n.checked_add(self.buckets * 8))
			.ok_or_else(|| io::Error::other("invalid recovery index offset"))
	}

	fn pointer(&mut self, offset: u64) -> io::Result<u64> {
		self.file.seek(SeekFrom::Start(offset))?;
		let mut bytes = [0; 8];
		self.file.read_exact(&mut bytes)?;
		Ok(u64::from_le_bytes(bytes))
	}

	fn set_pointer(&mut self, offset: u64, value: u64) -> io::Result<()> {
		self.file.seek(SeekFrom::Start(offset))?;
		self.file.write_all(&value.to_le_bytes())
	}

	pub(super) fn add(&mut self, key: &Key) -> io::Result<()> {
		let hash = Self::digest(key);
		let bucket = self.bucket(&hash);
		let next = self.pointer(bucket)?;
		let entry = self
			.entries
			.checked_add(1)
			.ok_or_else(|| io::Error::other("recovery index is too large"))?;
		let offset = self.offset(entry)?;
		self.file.seek(SeekFrom::Start(offset))?;
		self.file.write_all(&hash)?;
		self.file.write_all(&next.to_le_bytes())?;
		self.set_pointer(bucket, entry)?;
		self.entries = entry;
		Ok(())
	}

	pub(super) fn claim(&mut self, key: &Key) -> io::Result<bool> {
		let hash = Self::digest(key);
		let mut link = self.bucket(&hash);
		let mut entry = self.pointer(link)?;
		while entry != 0 {
			let offset = self.offset(entry)?;
			self.file.seek(SeekFrom::Start(offset))?;
			let mut stored = [0; 32];
			self.file.read_exact(&mut stored)?;
			let next = self.pointer(offset + 32)?;
			if stored == hash {
				self.set_pointer(link, next)?;
				return Ok(true);
			}
			link = offset + 32;
			entry = next;
		}
		Ok(false)
	}
}

#[cfg(test)]
#[path = "dedupe_disk_tests.rs"]
mod tests;
