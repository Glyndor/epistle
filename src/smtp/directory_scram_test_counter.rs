//! Test-only counter for [`super::directory::Directory::scram_credentials`]
//! lookups. The SCRAM listener tests assert this stays at zero when a ban
//! short-circuits the exchange: the ban check has to run before any SCRAM
//! credential lookup, and a stray lookup would let a banned IP probe
//! whether the account exists. The counter is a process-wide atomic
//! because the `Directory` struct already carries its full quota of
//! fields and the tests are the only callers; `cargo test` runs each
//! test in a fresh process state, so cross-test bleed is not a concern
//! in practice (the tests assert the *delta* from the start of the
//! case, not an absolute count).

use std::sync::atomic::{AtomicUsize, Ordering};

static SCRAM_CREDENTIALS_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Bump the counter. Called from
/// [`super::directory::Directory::scram_credentials`] before any real
/// work; the test-only `cargo test` build is the only caller.
pub fn record() {
	SCRAM_CREDENTIALS_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// How many times [`super::directory::Directory::scram_credentials`]
/// has been called since the start of the test process. The SCRAM
/// ban tests snapshot the counter before driving the exchange and
/// assert the delta is zero when a ban short-circuits the lookup.
pub fn count() -> usize {
	SCRAM_CREDENTIALS_CALLS.load(Ordering::Relaxed)
}
