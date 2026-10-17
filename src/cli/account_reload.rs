//! `epistle account …`: after a write, wait until the running server
//! has loaded it, so a script that adds an account and logs in at once
//! does not lose the race against the server's file-watch poll and
//! trip the brute-force ban.
//!
//! Lives in a sibling so `account.rs` stays under the per-file
//! code-line budget.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::directory_store::{ReloadWait, WaitError, reload_fingerprint, wait_for_reload};

/// How long one `epistle account …` command waits for the server's
/// reload: two poll intervals and a half, enough for a poll that
/// lands just after the write plus a slow reload.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(5);

/// The line printed when the server has not loaded the change in time.
pub(crate) const NOT_LOADED_NOTE: &str =
	"note: the running server has not loaded the change yet; it will within a few seconds";

/// How a wait after a write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
	/// The server reported the fingerprint of the write.
	Loaded,
	/// No server is polling, so there was nothing to wait for.
	NoServer,
	/// The server is polling but did not load the write in time.
	TimedOut,
}

/// Wait for the running server to load the write just made to `path`,
/// printing [`NOT_LOADED_NOTE`] on `err` when it has not within the
/// timeout. Always succeeds: the change is on disk either way, and a
/// non-zero exit would make a script retry a write that already
/// happened and fail on "already exists".
pub(crate) fn wait_after_write(path: &Path, err: &mut impl Write) -> ExitCode {
	wait_within(path, err, timeout());
	ExitCode::SUCCESS
}

/// [`wait_after_write`], reporting how the wait ended for a `--json`
/// result.
pub(crate) fn wait(path: &Path, err: &mut impl Write) -> Waited {
	wait_within(path, err, timeout())
}

/// [`wait_after_write`] with an explicit timeout, reporting how the
/// wait ended.
pub(crate) fn wait_within(path: &Path, err: &mut impl Write, timeout: Duration) -> Waited {
	let data_dir = path.parent().unwrap_or_else(|| Path::new("."));
	match wait_for_reload(data_dir, path, reload_fingerprint(path), timeout) {
		Ok(ReloadWait::Loaded) => Waited::Loaded,
		Ok(ReloadWait::NoServer) | Err(WaitError::NoFilename) => Waited::NoServer,
		Err(WaitError::Timeout) => {
			let _ = writeln!(err, "{NOT_LOADED_NOTE}");
			Waited::TimedOut
		}
	}
}

#[cfg(not(test))]
fn timeout() -> Duration {
	RELOAD_TIMEOUT
}

#[cfg(test)]
thread_local! {
	/// A shorter timeout for the command-level tests on this thread.
	static TIMEOUT_OVERRIDE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn timeout() -> Duration {
	TIMEOUT_OVERRIDE.get().unwrap_or(RELOAD_TIMEOUT)
}

/// Run `body` with the command-level wait cut to `timeout` on this
/// thread.
#[cfg(test)]
pub(crate) fn with_timeout<R>(timeout: Duration, body: impl FnOnce() -> R) -> R {
	TIMEOUT_OVERRIDE.set(Some(timeout));
	let result = body();
	TIMEOUT_OVERRIDE.set(None);
	result
}

#[cfg(test)]
#[path = "account_reload_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "account_reload_lock_tests.rs"]
mod lock_tests;
