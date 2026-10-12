//! The PostgreSQL implementation of [`crate::antispam::greylist::GreylistStore`].
//!
//! Kept apart from the pure decision logic in `greylist.rs` so the SQL-bound
//! half can be measured by the live database integration test alone. Every
//! `GreylistStore` method is async because the SQL queries are; the
//! in-memory store in `greylist.rs` returns already-ready futures so it can
//! share the same trait surface.

use sqlx::PgPool;

use super::greylist::{GreylistStore, StoreFuture, StoreUnavailable};

/// The production [`GreylistStore`]: the `greylist_triplet` table
/// keyed by the lowercase `triplet.key()` string. State survives a restart,
/// so legitimate senders do not re-defer every time the server reloads.
pub struct PgGreylistStore {
	pool: PgPool,
}

impl std::fmt::Debug for PgGreylistStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PgGreylistStore").finish()
	}
}

impl PgGreylistStore {
	/// Wrap a live pool. The table comes from the `0007_greylist.sql`
	/// migration applied at startup, so this constructor does not issue
	/// `CREATE TABLE` itself.
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

impl GreylistStore for PgGreylistStore {
	fn first_seen(&self, key: &str) -> StoreFuture<'_, Result<Option<u64>, StoreUnavailable>> {
		let key = key.to_string();
		Box::pin(async move {
			// Non-macro `sqlx::query`: avoids touching the offline
			// `.sqlx` cache every CI rerun would otherwise have to
			// revalidate.
			let row: Result<Option<(i64,)>, sqlx::Error> =
				sqlx::query_as("SELECT first_seen FROM greylist_triplet WHERE key = $1")
					.bind(&key)
					.fetch_optional(&self.pool)
					.await;
			match row {
				Ok(Some((first_seen,))) => Ok(Some(first_seen.max(0) as u64)),
				Ok(None) => Ok(None),
				// Reported as unavailable, never as "not seen": a first
				// sighting is deferred, so mapping an outage onto it would
				// defer every inbound message until the database is back.
				Err(error) => {
					tracing::warn!(%error, "greylist: lookup failed; accepting");
					Err(StoreUnavailable)
				}
			}
		})
	}

	fn record(&self, key: &str, now: u64) -> StoreFuture<'_, ()> {
		let key = key.to_string();
		Box::pin(async move {
			// `ON CONFLICT (key) DO UPDATE` keeps the `first_seen` that
			// already exists. A retry that arrives much later should not
			// reset the wait; only touch `last_seen`. `passed_at` is set
			// by callers that observe a successful retry, not here.
			let result = sqlx::query(
				"INSERT INTO greylist_triplet (key, first_seen, last_seen) \
				 VALUES ($1, $2, $2) \
				 ON CONFLICT (key) DO UPDATE SET \
				     last_seen = EXCLUDED.last_seen, \
				     updated_at = now()",
			)
			.bind(&key)
			.bind(now as i64)
			.execute(&self.pool)
			.await;
			if let Err(error) = result {
				tracing::warn!(%error, "greylist: insert failed; defer/accept will fall back to mem-only semantics");
			}
		})
	}

	fn sweep(&self, now: u64, max_age: u64) -> StoreFuture<'_, ()> {
		Box::pin(async move {
			// The lifetime policy: drop anything whose first sighting is
			// older than `max_age`. A row that was actively used
			// (`last_seen` close to `now`) but first seen long ago keeps
			// `first_seen` older than the window and is pruned too: the
			// row would have completed the delay long ago, and an
			// expired entry that never retried does not deserve a row.
			let horizon = now.saturating_sub(max_age) as i64;
			let result = sqlx::query("DELETE FROM greylist_triplet WHERE first_seen < $1")
				.bind(horizon)
				.execute(&self.pool)
				.await;
			if let Err(error) = result {
				tracing::warn!(%error, "greylist: sweep failed; stale rows remain in the table");
			}
		})
	}
}
