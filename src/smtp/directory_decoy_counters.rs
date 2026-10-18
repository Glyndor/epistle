//! Test-only counts of the stand-in work a directory does for a login with no
//! credential of its own: the password hash checked for an unknown, disabled or
//! receive-only login, and the decoy SCRAM credentials built for one. A test
//! that asserts the unknown-login path ran the same work as a real login reads
//! these instead of a clock. The counters belong to one directory, so tests that
//! run in parallel do not see each other's.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::Directory;

/// How many times each stand-in ran.
#[derive(Debug, Default)]
pub(crate) struct DecoyCounters {
	password: AtomicUsize,
	scram: AtomicUsize,
}

impl DecoyCounters {
	/// Password hashes checked for a login with no password of its own.
	pub(crate) fn password(&self) -> usize {
		self.password.load(Ordering::Relaxed)
	}

	/// Decoy SCRAM credential sets built.
	pub(crate) fn scram(&self) -> usize {
		self.scram.load(Ordering::Relaxed)
	}
}

impl Directory {
	/// Attach counters to this directory.
	pub(crate) fn with_decoy_counters(mut self, counters: Arc<DecoyCounters>) -> Self {
		self.decoy_counters = Some(counters);
		self
	}

	pub(super) fn count_password_decoy(&self) {
		if let Some(counters) = &self.decoy_counters {
			counters.password.fetch_add(1, Ordering::Relaxed);
		}
	}

	pub(super) fn count_scram_decoy(&self) {
		if let Some(counters) = &self.decoy_counters {
			counters.scram.fetch_add(1, Ordering::Relaxed);
		}
	}
}
