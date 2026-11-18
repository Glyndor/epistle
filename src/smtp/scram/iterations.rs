//! The iteration count of the SCRAM verifiers the server derives (`[auth]
//! scram_iterations`), process-wide.
//!
//! A verifier stores the count it was derived with, so changing the setting
//! never invalidates one: a verifier below the count in force is replaced the
//! next time its account signs in with a cleartext password mechanism, which
//! is also how a raised count reaches the accounts that already have one. The
//! default is the OWASP minimum for PBKDF2-HMAC-SHA256, 600000, which is also
//! the floor the loader enforces; the setting can only raise it.

use std::sync::atomic::{AtomicU32, Ordering};

use super::SCRAM_ITERATIONS;

/// The highest count the loader accepts, so one sign-in cannot be asked for
/// seconds of CPU.
pub const CEILING: u32 = 10_000_000;

static CURRENT: AtomicU32 = AtomicU32::new(SCRAM_ITERATIONS);

/// Refuse a count below the OWASP floor or above [`CEILING`].
pub fn validate(iterations: u32) -> Result<(), String> {
	if iterations < SCRAM_ITERATIONS {
		return Err(format!(
			"[auth] scram_iterations ({iterations}) must be at least {SCRAM_ITERATIONS}: the OWASP \
			 minimum for PBKDF2-HMAC-SHA256"
		));
	}
	if iterations > CEILING {
		return Err(format!(
			"[auth] scram_iterations ({iterations}) must be at most {CEILING}"
		));
	}
	Ok(())
}

#[cfg(test)]
thread_local! {
	static SCOPED: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// The count a new verifier is derived with.
pub fn current() -> u32 {
	#[cfg(test)]
	if let Some(scoped) = SCOPED.with(|cell| cell.get()) {
		return scoped;
	}
	CURRENT.load(Ordering::Relaxed)
}

/// Run `body` with `iterations` in force on this thread only, so a test of a
/// non-default count cannot reach the tests that run beside it.
#[cfg(test)]
pub(crate) fn scoped<R>(iterations: u32, body: impl FnOnce() -> R) -> R {
	struct Restore(Option<u32>);
	impl Drop for Restore {
		fn drop(&mut self) {
			SCOPED.with(|cell| cell.set(self.0));
		}
	}
	let _restore = Restore(SCOPED.with(|cell| cell.replace(Some(iterations))));
	body()
}

/// Put `iterations` in force for the verifiers derived from now on.
pub fn install(iterations: u32) {
	CURRENT.store(iterations, Ordering::Relaxed);
}
