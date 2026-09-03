//! Shared authentication ban store.
//!
//! Every listener (SMTP submission, IMAP, POP3, ManageSieve, the API, OAuth
//! grants) records its authentication failures here, and every listener
//! asks this store whether the subject (a client IP or an account name) is
//! banned before doing any password hashing. The product context's defaults
//! drive the policy: 5 failed authentications in 15 minutes trigger a ban;
//! the first ban lasts 15 minutes, the next on the same subject 30 minutes,
//! then an hour, ... capped at 24 hours. A successful authentication
//! clears both the ban and the failure history for the subject.
//!
//! The store is **fail open on database errors**: a connection hiccup must
//! never block mail, so every public method returns the safe answer (`None`
//! for a ban check, `()` for a record/clear) and logs once per minute while
//! bumping the `database_unavailable` counter. The reputation screen, the
//! one place this discipline already lives, follows the same rule.
//!
//! Times travel as Unix-seconds (`u64`); the SQL bindings cast them to
//! `timestamptz` via `to_timestamp` so the store does not pull a chrono
//! or `time` dependency.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::metrics::Metrics;

/// The active ban for a subject: when it expires and the rule that fired it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanInfo {
	/// The Unix timestamp (seconds) the ban ends; the directory refuses
	/// every authentication for this subject while `now < until_secs`.
	pub until_secs: u64,
	/// The rule that fired the ban, kept verbatim for the audit log
	/// (`auth.banned` event). The wire reply never includes it.
	pub reason: String,
}

/// The ban policy. Holds the four numbers that drive the backoff so the
/// unit tests can shrink the rolling window and the 24-hour cap to seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPolicy {
	/// The rolling window (seconds) used to count failures: failures
	/// outside the window do not contribute to the threshold.
	pub window_secs: u64,
	/// The number of failures within the rolling window that fires a ban.
	pub threshold: u32,
	/// The base ban duration. The first ban is `base_secs` long, the next
	/// is `base_secs * 2`, then `base_secs * 4`, etc.
	pub base_secs: u64,
	/// The maximum ban duration, regardless of how many bans have stacked.
	pub max_secs: u64,
}

impl Default for BanPolicy {
	fn default() -> Self {
		Self {
			// The product context's defaults: 15 minutes, 5 failures, base
			// 15 minutes, capped at 24 hours.
			window_secs: 15 * 60,
			threshold: 5,
			base_secs: 15 * 60,
			max_secs: 24 * 60 * 60,
		}
	}
}

impl BanPolicy {
	/// How long the next ban lasts given the current `strikes` count. The
	/// first ban (strikes = 1) is `base_secs`; each subsequent ban doubles
	/// it, capped at `max_secs`. Saturates the exponent at 20 so the
	/// shift cannot overflow.
	fn duration_for(&self, strikes: u32) -> Duration {
		let exponent = strikes.saturating_sub(1).min(20);
		let multiplier = 1u64 << exponent;
		let secs = self.base_secs.saturating_mul(multiplier).min(self.max_secs);
		Duration::from_secs(secs)
	}
}

/// The ban store interface consulted by every listener. The production
/// implementation is [`PgBanStore`] (PostgreSQL-backed); the tests use
/// [`crate::antispam::bans_tests::FakeBanStore`]. The directory holds an
/// `Option<Arc<dyn BanStore>>` so a deployment without `[database]`
/// degrades to the per-connection three-strikes counters.
pub trait BanStore: std::fmt::Debug + Send + Sync {
	/// Record one authentication failure for `subject` on `protocol` at
	/// `now_secs` (Unix seconds).
	fn record_failure(
		&self,
		subject: &str,
		protocol: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Whether `subject` is currently banned. `None` when the subject is
	/// clean, or when the lookup failed (fail open).
	fn is_banned(
		&self,
		subject: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<BanInfo>> + Send + '_>>;

	/// A successful authentication clears the ban and the failure
	/// history for `subject`.
	fn clear_success(
		&self,
		subject: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Drop failures older than 24 hours and bans whose `until` is older
	/// than 24 hours ago.
	fn sweep(
		&self,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Drop every row for `account`, called from
	/// [`crate::directory_store::removal::remove_account`].
	fn remove_account(
		&self,
		account: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// Build the canonical `'ip:<addr>'` subject for `ip`.
pub fn subject_ip(ip: IpAddr) -> String {
	format!("ip:{ip}")
}

/// Build the canonical `'account:<login>'` subject for `account`.
pub fn subject_account(account: &str) -> String {
	format!("account:{}", account.to_ascii_lowercase())
}

/// The PostgreSQL-backed ban store: the production implementation of
/// [`BanStore`]. One instance per process, shared across listeners.
pub struct PgBanStore {
	pool: PgPool,
	policy: BanPolicy,
	metrics: Option<Arc<Metrics>>,
	/// Last time the fail-open path logged a warning, so a flapping pool
	/// does not flood the log. `Mutex` because every public method may
	/// touch it from a different async task.
	last_warn: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for PgBanStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PgBanStore")
			.field("policy", &self.policy)
			.field("has_metrics", &self.metrics.is_some())
			.finish()
	}
}

impl PgBanStore {
	/// Build a store with the default policy (the product context's
	/// 15-minute window, 5-failure threshold, 24-hour cap).
	pub fn new(pool: PgPool, metrics: Option<Arc<Metrics>>) -> Self {
		Self {
			pool,
			policy: BanPolicy::default(),
			metrics,
			last_warn: Mutex::new(None),
		}
	}

	/// Build a store with a custom policy. Used by the integration tests
	/// to shrink the window and the cap.
	pub fn with_policy(
		pool: PgPool,
		metrics: Option<Arc<Metrics>>,
		policy: BanPolicy,
	) -> Self {
		Self {
			pool,
			policy,
			metrics,
			last_warn: Mutex::new(None),
		}
	}

	/// The live policy. Public so callers (and tests) can assert the
	/// active thresholds without re-parsing them.
	pub fn policy(&self) -> BanPolicy {
		self.policy
	}

	/// One warn per minute, plus the metrics counter. The reputation
	/// screen follows the same pattern.
	async fn record_db_error(&self, error: &sqlx::Error) {
		if let Some(metrics) = &self.metrics {
			metrics.database_unavailable();
		}
		let mut last = self.last_warn.lock().await;
		let should_log = match *last {
			Some(prev) => prev.elapsed() >= Duration::from_secs(60),
			None => true,
		};
		if should_log {
			tracing::warn!(%error, "ban store: database unavailable; failing open");
			*last = Some(Instant::now());
		}
	}
}

impl BanStore for PgBanStore {
	fn record_failure(
		&self,
		subject: &str,
		protocol: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		let protocol = protocol.to_string();
		Box::pin(async move { self.record_failure_inner(&subject, &protocol, now_secs).await })
	}

	fn is_banned(
		&self,
		subject: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<BanInfo>> + Send + '_>> {
		let subject = subject.to_string();
		Box::pin(async move { self.is_banned_inner(&subject, now_secs).await })
	}

	fn clear_success(
		&self,
		subject: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		Box::pin(async move { self.clear_success_inner(&subject).await })
	}

	fn sweep(
		&self,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		Box::pin(async move { self.sweep_inner(now_secs).await })
	}

	fn remove_account(
		&self,
		account: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let account = account.to_string();
		Box::pin(async move { self.remove_account_inner(&account).await })
	}
}

impl PgBanStore {
	async fn record_failure_inner(&self, subject: &str, protocol: &str, now_secs: u64) {
		let id = Uuid::now_v7();
		let window_start_secs = now_secs.saturating_sub(self.policy.window_secs);
		let result = async {
			let mut tx = self.pool.begin().await?;
			sqlx::query(
				"INSERT INTO auth_failure (id, subject, protocol, seen_at) \
				 VALUES ($1, $2, $3, to_timestamp($4))",
			)
			.bind(id)
			.bind(subject)
			.bind(protocol)
			.bind(now_secs as i64)
			.execute(&mut *tx)
			.await?;
			let count: i64 = sqlx::query_scalar(
				"SELECT count(*) FROM auth_failure \
				 WHERE subject = $1 AND seen_at >= to_timestamp($2)",
			)
			.bind(subject)
			.bind(window_start_secs as i64)
			.fetch_one(&mut *tx)
			.await?;
			if count >= self.policy.threshold as i64 {
				let reason = format!(
					"{} failed authentications in {} seconds",
					self.policy.threshold, self.policy.window_secs
				);
				let existing: Option<(i32,)> = sqlx::query_as(
					"SELECT strikes FROM auth_ban WHERE subject = $1 FOR UPDATE",
				)
				.bind(subject)
				.fetch_optional(&mut *tx)
				.await?;
				let strikes: u32 = existing
					.map(|(s,)| u32::try_from(s).unwrap_or(0))
					.unwrap_or(0)
					.saturating_add(1);
				let duration = self.policy.duration_for(strikes);
				let until_secs = now_secs.saturating_add(duration.as_secs());
				sqlx::query(
					"INSERT INTO auth_ban (subject, strikes, until, reason, \
					 created_at, updated_at) VALUES ($1, $2, to_timestamp($3), $4, \
					 to_timestamp($5), to_timestamp($5)) \
					 ON CONFLICT (subject) DO UPDATE SET \
					 strikes = EXCLUDED.strikes, \
					 until = EXCLUDED.until, \
					 reason = EXCLUDED.reason, \
					 updated_at = EXCLUDED.updated_at",
				)
				.bind(subject)
				.bind(strikes as i32)
				.bind(until_secs as i64)
				.bind(&reason)
				.bind(now_secs as i64)
				.execute(&mut *tx)
				.await?;
			}
			tx.commit().await?;
			Ok::<(), sqlx::Error>(())
		}
		.await;
		if let Err(error) = result {
			self.record_db_error(&error).await;
		}
	}

	async fn is_banned_inner(&self, subject: &str, now_secs: u64) -> Option<BanInfo> {
		let row: Result<Option<(i64, String)>, sqlx::Error> = sqlx::query_as(
			"SELECT \
			         EXTRACT(EPOCH FROM until)::BIGINT, \
			         reason \
			     FROM auth_ban WHERE subject = $1 AND until > to_timestamp($2)",
		)
		.bind(subject)
		.bind(now_secs as i64)
		.fetch_optional(&self.pool)
		.await;
		match row {
			Ok(Some((until, reason))) => Some(BanInfo {
				until_secs: until.max(0) as u64,
				reason,
			}),
			Ok(None) => None,
			Err(error) => {
				self.record_db_error(&error).await;
				None
			}
		}
	}

	async fn clear_success_inner(&self, subject: &str) {
		let result = async {
			let mut tx = self.pool.begin().await?;
			sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
				.bind(subject)
				.execute(&mut *tx)
				.await?;
			sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
				.bind(subject)
				.execute(&mut *tx)
				.await?;
			tx.commit().await?;
			Ok::<(), sqlx::Error>(())
		}
		.await;
		if let Err(error) = result {
			self.record_db_error(&error).await;
		}
	}

	async fn sweep_inner(&self, now_secs: u64) {
		let horizon = now_secs.saturating_sub(24 * 60 * 60);
		let result = async {
			sqlx::query("DELETE FROM auth_failure WHERE seen_at < to_timestamp($1)")
				.bind(horizon as i64)
				.execute(&self.pool)
				.await?;
			sqlx::query("DELETE FROM auth_ban WHERE until < to_timestamp($1)")
				.bind(horizon as i64)
				.execute(&self.pool)
				.await?;
			Ok::<(), sqlx::Error>(())
		}
		.await;
		if let Err(error) = result {
			self.record_db_error(&error).await;
		}
	}

	async fn remove_account_inner(&self, account: &str) {
		let subject = subject_account(account);
		let result = async {
			let mut tx = self.pool.begin().await?;
			sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
				.bind(&subject)
				.execute(&mut *tx)
				.await?;
			sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
				.bind(&subject)
				.execute(&mut *tx)
				.await?;
			tx.commit().await?;
			Ok::<(), sqlx::Error>(())
		}
		.await;
		if let Err(error) = result {
			self.record_db_error(&error).await;
		}
	}
}

#[cfg(test)]
#[path = "bans_tests.rs"]
mod tests;
