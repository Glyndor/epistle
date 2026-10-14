//! Server-wide byte budget for SMTP DATA / BDAT.
//!
//! The SMTP server buffers every message body in memory until end-of-DATA: a
//! 25 MiB message sits in one `Vec<u8>` for every concurrent transfer, and
//! the post-DATA stamping path makes several more full copies before the
//! bytes reach the spool. With up to a thousand concurrent connections per
//! listener, a few dozen large messages exhaust the mail container's
//! `mem_limit`.
//!
//! The budget is a single, shared `Arc<MemoryBudget>` every session draws
//! from. A `try_reserve` call claims `n` bytes for the lifetime of one
//! in-flight transfer; the matching `release` runs on every path that drops
//! the reservation (success, error, disconnect, panic). When the budget is
//! exhausted a new transaction is told `452 4.3.1 insufficient system
//! resources; try again later` at DATA, and a BDAT chunk that would push
//! past the cap is refused the same way.
//!
//! The default cap is derived from the container memory the operator
//! configured in `init` answers (1 GiB for `mail`), a quarter of it
//! rounded down to the nearest MiB, so a busy server stays well clear of
//! the OOM. A `[server] message_memory_budget` overrides the derived
//! default; setting it to `0` disables the budget (every reservation
//! succeeds, the historical behaviour).

use std::sync::Mutex;

/// Default byte budget for the DATA / BDAT path when no
/// `[server] message_memory_budget` is configured. A quarter of the
/// container's `mem_limit 1g` rounded down to the nearest MiB keeps the
/// worst case below the cgroup ceiling even when every connection has a
/// full message buffered.
pub const DEFAULT_BUDGET_BYTES: u64 = 256 * 1024 * 1024;

/// A shared byte budget for in-flight SMTP message transfers. Every
/// session holds an `Arc<MemoryBudget>` and reserves from it on DATA and
/// every BDAT chunk. Reservations are released on every path that drops
/// the in-flight body.
pub struct MemoryBudget {
	cap: u64,
	used: Mutex<u64>,
}

impl std::fmt::Debug for MemoryBudget {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let used = *self.used.lock().expect("memory budget");
		formatter
			.debug_struct("MemoryBudget")
			.field("cap", &self.cap)
			.field("used", &used)
			.finish()
	}
}

impl MemoryBudget {
	/// A budget that admits every reservation. The historical behaviour
	/// for `[server] message_memory_budget = 0` and the default for
	/// tests that do not wire the budget in.
	pub fn unlimited() -> Self {
		MemoryBudget {
			cap: 0,
			used: Mutex::new(0),
		}
	}

	/// A budget with the given cap in bytes. `0` is the unlimited
	/// variant; any positive value is the upper bound on the sum of
	/// in-flight reservations.
	pub fn with_cap(cap: u64) -> Self {
		MemoryBudget {
			cap,
			used: Mutex::new(0),
		}
	}

	/// The configured cap, in bytes. `0` means unlimited.
	pub fn cap(&self) -> u64 {
		self.cap
	}

	/// The bytes currently reserved. Includes DATA, BDAT chunks that have
	/// been admitted but not yet finalized, and reservations that have not
	/// been released yet on a slow path.
	pub fn used(&self) -> u64 {
		*self.used.lock().expect("memory budget")
	}

	/// Try to claim `bytes` octets from the budget. `Ok(())` when the
	/// reservation fits (or the budget is unlimited), `Err(required)` with
	/// the number of bytes the caller asked for when the reservation
	/// would exceed the cap. The caller is expected to call [`Self::release`]
	/// with the same `bytes` on every path that drops the reservation.
	pub fn try_reserve(&self, bytes: u64) -> Result<(), u64> {
		if self.cap == 0 {
			return Ok(());
		}
		if bytes > self.cap {
			return Err(bytes);
		}
		let mut used = self.used.lock().expect("memory budget");
		if used.saturating_add(bytes) > self.cap {
			return Err(bytes);
		}
		*used = used.saturating_add(bytes);
		Ok(())
	}

	/// Release a reservation previously made with [`Self::try_reserve`].
	/// Saturating: a `release` larger than what was reserved is a no-op
	/// (the extra is clamped to zero), so a path that double-releases on
	/// success and on disconnect does not underflow the counter.
	pub fn release(&self, bytes: u64) {
		if self.cap == 0 || bytes == 0 {
			return;
		}
		let mut used = self.used.lock().expect("memory budget");
		*used = used.saturating_sub(bytes);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unlimited_admits_every_reservation() {
		let budget = MemoryBudget::unlimited();
		assert!(budget.try_reserve(1).is_ok());
		assert!(budget.try_reserve(usize::MAX as u64).is_ok());
	}

	#[test]
	fn reservation_fails_when_over_cap() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(60).is_ok());
		assert_eq!(budget.try_reserve(50), Err(50));
		assert_eq!(budget.used(), 60);
	}

	#[test]
	fn release_frees_the_bytes_for_the_next_reservation() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(60).is_ok());
		budget.release(60);
		assert!(budget.try_reserve(80).is_ok());
	}

	#[test]
	fn release_saturates_on_over_release() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(40).is_ok());
		budget.release(200);
		assert_eq!(budget.used(), 0);
	}
}
