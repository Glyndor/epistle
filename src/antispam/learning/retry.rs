//! A transaction PostgreSQL abandoned is tried again, a few times.
//!
//! Two transactions that need the same rows can still be set against each
//! other by the server (a deadlock, a serialization failure) even when every
//! path takes its locks in the order written in [`super::ledger`]. The loser
//! lost nothing, so running it again is safe; the number of attempts and the
//! wait between them are fixed, so a database that keeps refusing is reported
//! rather than hammered.

use std::future::Future;
use std::time::Duration;

/// Attempts of one transaction, the first included.
pub const MAX_ATTEMPTS: u32 = 4;

/// SQLSTATE of a deadlock and of a serialization failure.
const RETRYABLE: [&str; 2] = ["40P01", "40001"];

/// Whether PostgreSQL abandoned the transaction and a new one may succeed.
pub fn is_retryable(error: &sqlx::Error) -> bool {
	matches!(
		error,
		sqlx::Error::Database(database)
			if database.code().is_some_and(|code| RETRYABLE.contains(&code.as_ref()))
	)
}

/// Run `attempt` until it succeeds, fails for another reason, or has been
/// abandoned [`MAX_ATTEMPTS`] times.
pub async fn retrying<T, F, Fut>(mut attempt: F) -> Result<T, sqlx::Error>
where
	F: FnMut() -> Fut,
	Fut: Future<Output = Result<T, sqlx::Error>>,
{
	let mut tries = 1;
	loop {
		match attempt().await {
			Err(error) if tries < MAX_ATTEMPTS && is_retryable(&error) => {
				tokio::time::sleep(Duration::from_millis(10 * u64::from(tries))).await;
				tries += 1;
			}
			other => return other,
		}
	}
}
