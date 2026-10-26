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
	/// When the whole run has to stop, for the steps that do not await.
	pub(super) deadline: Option<std::time::Instant>,
}

impl Default for Budget {
	fn default() -> Self {
		Self {
			mailbox_limit: 16 * 1024 * 1024,
			total_limit: 64 * 1024 * 1024,
			mailbox: 0,
			total: 0,
			deadline: None,
		}
	}
}

impl Budget {
	/// Stop a synchronous step once the run's total deadline has passed. The
	/// timeout around the run only fires where the run awaits, which a scan of
	/// the local mailbox never does.
	pub(super) fn check_deadline(&self) -> Result<(), super::MigrateError> {
		match self.deadline {
			Some(at) if std::time::Instant::now() >= at => Err(super::MigrateError::Timeout),
			_ => Ok(()),
		}
	}

	pub(super) fn next_mailbox(&mut self) {
		self.mailbox = 0;
	}

	/// Charge a buffer that is freed when the folder ends: it counts against
	/// the folder's limit while it is held, but never against the total, so
	/// a long list of folders does not add up to a total nobody holds.
	pub(super) fn charge_transient(&mut self, bytes: usize) -> Result<(), ClientError> {
		if bytes > self.mailbox_limit.saturating_sub(self.mailbox) {
			return Err(ClientError::Metadata {
				scope: "mailbox",
				limit: self.mailbox_limit,
			});
		}
		self.mailbox += bytes;
		Ok(())
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
