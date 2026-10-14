//! `epistle account …`: wait until the running server has reloaded
//! the change a mutator just wrote, so a script that adds an account
//! and logs in at once does not lose the race against the server's
//! two-second file-watch poll and trip the brute-force ban.
//!
//! Lives in a sibling so `account.rs` stays under the per-file
//! code-line budget.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::directory_store::{WaitError, reload_fingerprint, wait_for_reload};

/// How long a single `epistle account …` command is willing to wait
/// for the server's reload. Five seconds matches the 5 s deadline the
/// task brief calls out: longer than the two-second poll cycle, with
/// a couple of cycles of slack for a slow disk or a busy server.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait for the running server to have reloaded `path` to the version
/// the CLI just wrote. The function is silent on success and on the
/// "no server" path (the status file is absent or empty), and prints
/// a single warning line on the supplied writer when the wait times
/// out.
///
/// Returns `ExitCode::SUCCESS` for both "the server reported a
/// matching fingerprint" and "no server appears to be running", and
/// `ExitCode::FAILURE` on a timeout, so callers can write
/// `wait_for_reload_or_warn(...)?` from a function whose
/// happy-path return is `ExitCode::SUCCESS`.
pub fn wait_for_reload_or_warn<W: Write>(
	path: &Path,
	status: &mut W,
) -> Result<ExitCode, ExitCode> {
	wait_for_reload_or_warn_within(path, status, RELOAD_TIMEOUT)
}

/// Same as [`wait_for_reload_or_warn`] but with a caller-supplied
/// timeout. Used by the test suite to keep a "stale status" assertion
/// inside the unit-test budget; production code should call
/// [`wait_for_reload_or_warn`] instead.
pub fn wait_for_reload_or_warn_within<W: Write>(
	path: &Path,
	status: &mut W,
	timeout: Duration,
) -> Result<ExitCode, ExitCode> {
	let target = reload_fingerprint(path);
	match wait_for_reload(
		path.parent().unwrap_or_else(|| Path::new(".")),
		path,
		target,
		timeout,
	) {
		Ok(()) => Ok(ExitCode::SUCCESS),
		Err(WaitError::Timeout) => {
			let _ = writeln!(
				status,
				"warning: the server has not picked the change up yet; \
				 the next authentication attempt may still hit the pre-edit directory"
			);
			Ok(ExitCode::FAILURE)
		}
		Err(WaitError::NoFilename) => Ok(ExitCode::SUCCESS),
	}
}
#[cfg(test)]
#[path = "account_reload_tests.rs"]
mod tests;
