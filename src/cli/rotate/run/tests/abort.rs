//! The kill switch of the crash tests: a child process given
//! `EPISTLE_TEST_ROTATE_ABORT_AT=N` aborts at the N-th checkpoint of the run.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The variable that arms the switch.
pub(in crate::cli::rotate) const ABORT_AT: &str = "EPISTLE_TEST_ROTATE_ABORT_AT";

static PASSED: AtomicUsize = AtomicUsize::new(0);

/// Count a checkpoint, and abort the process at the armed one.
pub(in crate::cli::rotate) fn checkpoint() {
	let Some(at) = std::env::var(ABORT_AT)
		.ok()
		.and_then(|value| value.parse::<usize>().ok())
	else {
		return;
	};
	if PASSED.fetch_add(1, Ordering::SeqCst) + 1 == at {
		std::process::abort();
	}
}
