//! Test-only counter for [`super::directory::Directory::scram_credentials`]
//! lookups. The SCRAM listener tests assert this stays at zero when a ban
//! short-circuits the exchange: the ban check has to run before any SCRAM
//! credential lookup, and a stray lookup would let a banned IP probe
//! whether the account exists. The counter is per-Directory (set via
//! [`super::directory::Directory::with_scram_lookup_counter`]) so
//! `cargo test`'s parallel tests in one process do not race on a shared
//! atomic; each test injects its own `Arc<AtomicUsize>` and asserts
//! the delta from the start of the case, not the absolute count.

use std::sync::atomic::{AtomicUsize, Ordering};

/// A fresh per-test counter. The caller wraps it in `Arc` and passes
/// it to [`super::directory::Directory::with_scram_lookup_counter`].
pub fn fresh() -> std::sync::Arc<AtomicUsize> {
	std::sync::Arc::new(AtomicUsize::new(0))
}

/// Bump the counter. Called from
/// [`super::directory::Directory::scram_credentials`] before any real
/// work; the test-only `cargo test` build is the only caller.
pub fn record(counter: &AtomicUsize) {
	counter.fetch_add(1, Ordering::Relaxed);
}

/// Read the counter the SCRAM ban tests snapshot before driving the
/// exchange and assert the delta is zero when a ban short-circuits
/// the lookup.
pub fn count(counter: &AtomicUsize) -> usize {
	counter.load(Ordering::Relaxed)
}
