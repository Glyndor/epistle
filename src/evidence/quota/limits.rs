//! The limits of one UTC day and how a share is fitted to them.

/// The fewest accounts' shares the day's limit must hold.
pub const MIN_SHARES: u64 = 4;

/// The limits, per UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Records (an acceptance and the outcomes it owes) one account may add:
	/// its share of the day.
	pub account_records: u64,
	/// Bytes one account may keep in full.
	pub account_kept_bytes: u64,
	/// Records of every kind the whole log may take.
	pub day_records: u64,
}

impl Default for Limits {
	fn default() -> Self {
		Limits {
			account_records: 500_000,
			account_kept_bytes: 4 * 1024 * 1024 * 1024,
			day_records: 5_000_000,
		}
	}
}

impl Limits {
	/// The limits with the share cut down so that [`MIN_SHARES`] of them fit
	/// the day, when it was set larger.
	pub fn fitted(mut self) -> Self {
		self.account_records = self.account_records.min(self.day_records / MIN_SHARES);
		self
	}
}
