//! Per-directory SCRAM lookup instrumentation for listener tests.

use super::super::Directory;

impl Directory {
	/// Test-only: attach a per-directory SCRAM credential-lookup
	/// counter.
	pub fn with_scram_lookup_counter(
		mut self,
		counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
	) -> Self {
		self.scram_lookup_counter = Some(counter);
		self
	}

	pub(super) fn record_scram_lookup(&self) {
		// Test-only: bump the per-directory lookup counter so the ban
		// tests can assert the SCRAM credential lookup never happens
		// when a ban short-circuits the exchange. The counter is
		// per-Directory (set via `with_scram_lookup_counter`) so parallel
		// tests in the same process do not race on a shared atomic.
		if let Some(counter) = self.scram_lookup_counter.as_ref() {
			counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		}
	}
}
