//! Conservative bounds on retained IMAP metadata, independent of message bodies.

use super::client::ClientError;

/// Largest mailbox or namespace literal, checked before reading its contents.
pub(super) const MAX_NAME_BYTES: usize = 1024;

/// Metadata allowance for one folder and for all folders visited in a run.
pub(super) struct Budget {
	pub(super) mailbox_limit: usize,
	pub(super) total_limit: usize,
	mailbox: usize,
	total: usize,
}

impl Default for Budget {
	fn default() -> Self {
		Self {
			mailbox_limit: 16 * 1024 * 1024,
			total_limit: 64 * 1024 * 1024,
			mailbox: 0,
			total: 0,
		}
	}
}

impl Budget {
	pub(super) fn next_mailbox(&mut self) {
		self.mailbox = 0;
	}

	pub(super) fn charge(&mut self, bytes: usize) -> Result<(), ClientError> {
		for (scope, used, limit) in [
			("mailbox", self.mailbox, self.mailbox_limit),
			("total", self.total, self.total_limit),
		] {
			if bytes > limit.saturating_sub(used) {
				return Err(ClientError::Metadata { scope, limit });
			}
		}
		self.mailbox += bytes;
		self.total += bytes;
		Ok(())
	}
}
