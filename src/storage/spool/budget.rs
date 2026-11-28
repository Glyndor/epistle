//! What one request may read of the queue.
//!
//! The queue is shared by every tenant and grows with what they send, so a
//! request that walks it carries a budget: so many entries and so many bytes
//! of envelope. The walk stops when either is spent and says that it did. The
//! entry that spends the last of it is still read whole, so a walk always
//! moves forward, however large one envelope is.

/// Most queue entries one request reads.
pub const MOST_ENTRIES: usize = 10_000;

/// Most bytes of envelope one request reads, but for the entry that spends the
/// last of them.
pub const MOST_BYTES: usize = 16 * 1024 * 1024;

/// What a request may still read of the queue.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
	entries: usize,
	bytes: usize,
}

impl Budget {
	/// A budget of `entries` entries and `bytes` bytes of envelope.
	pub fn new(entries: usize, bytes: usize) -> Self {
		Self { entries, bytes }
	}

	/// The budget a request that reads the queue starts with.
	pub fn standard() -> Self {
		Self::new(MOST_ENTRIES, MOST_BYTES)
	}

	/// The entries the request may still read.
	pub fn entries(&self) -> usize {
		self.entries
	}

	/// True when the request may read no further entry.
	pub fn is_spent(&self) -> bool {
		self.entries == 0 || self.bytes == 0
	}

	/// Count one entry read, of `bytes` bytes of envelope.
	pub(super) fn charge(&mut self, bytes: usize) {
		self.entries = self.entries.saturating_sub(1);
		self.bytes = self.bytes.saturating_sub(bytes);
	}
}
