//! The PostgreSQL implementation of [`BanStore`]. Kept apart from the
//! policy and the trait so the SQL-bound half can be measured by the live
//! database job alone; everything with a pure answer stays in `src/antispam/bans/mod.rs`.

use super::*;
use crate::metrics::Metrics;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

mod admin;
pub use admin::{BanRow, BanTarget, MANUAL_REASON, UnbanTarget, parse_allow, parse_login};

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
	pub fn with_policy(pool: PgPool, metrics: Option<Arc<Metrics>>, policy: BanPolicy) -> Self {
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

/// Serialize every writer of one subject for the rest of the transaction.
/// Without it, two concurrent failures each count only the rows already
/// committed, so both read a count under the threshold and the ban never
/// fires; the `FOR UPDATE` on `auth_ban` cannot help, because the row may
/// not exist yet. The lock is released at commit or rollback.
async fn lock_subject(
	tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
	subject: &str,
) -> Result<(), sqlx::Error> {
	sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
		.bind(subject)
		.execute(&mut **tx)
		.await?;
	Ok(())
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
		Box::pin(async move {
			self.record_failure_inner(&subject, &protocol, now_secs)
				.await
		})
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
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		Box::pin(async move { self.clear_success_inner(&subject, now_secs).await })
	}

	fn is_allow_listed(
		&self,
		ip: IpAddr,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
		Box::pin(async move { self.ip_allowed(ip).await })
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

	fn is_known_network(
		&self,
		account: &str,
		ip: IpAddr,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
		let account = account.to_string();
		Box::pin(async move { self.is_known_network_inner(&account, ip, now_secs).await })
	}

	fn record_known_network(
		&self,
		account: &str,
		ip: IpAddr,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let account = account.to_string();
		Box::pin(async move {
			self.record_known_network_inner(&account, ip, now_secs)
				.await
		})
	}
}

impl PgBanStore {
	async fn record_failure_inner(&self, subject: &str, protocol: &str, now_secs: u64) {
		// An allow-listed client is never counted, so it can never reach the
		// threshold however many times it fails.
		if let Some(ip) = admin::ip_of_subject(subject)
			&& self.ip_allowed(ip).await
		{
			return;
		}
		let id = Uuid::now_v7();
		let window_start_secs = now_secs.saturating_sub(self.policy.window_secs);
		let result = async {
			let mut tx = self.pool.begin().await?;
			lock_subject(&mut tx, subject).await?;
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
			let threshold = self.policy.threshold_for(subject);
			if count >= threshold as i64 {
				let reason = format!(
					"{threshold} failed authentications in {} seconds",
					self.policy.window_secs
				);
				let existing: Option<(i32,)> =
					sqlx::query_as("SELECT strikes FROM auth_ban WHERE subject = $1 FOR UPDATE")
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

	/// Ban check for a client address: the allow list wins over every ban, and
	/// a ban on the exact address or on a network containing it applies. One
	/// query returns both, so the common clean case costs a single round trip.
	async fn is_ip_banned(&self, ip: IpAddr, now_secs: u64) -> Option<BanInfo> {
		let rows: Result<Vec<(String, String, i64, String)>, sqlx::Error> = sqlx::query_as(
			"SELECT 'allow', cidr, 0::BIGINT, '' FROM auth_allow \
			 UNION ALL \
			 SELECT 'ban', subject, EXTRACT(EPOCH FROM until)::BIGINT, reason \
			 FROM auth_ban WHERE (subject = $1 OR subject LIKE 'cidr:%') \
			 AND until > to_timestamp($2)",
		)
		.bind(subject_ip(ip))
		.bind(now_secs as i64)
		.fetch_all(&self.pool)
		.await;
		let rows = match rows {
			Ok(rows) => rows,
			Err(error) => {
				self.record_db_error(&error).await;
				return None;
			}
		};
		let allowed: Vec<String> = rows
			.iter()
			.filter(|row| row.0 == "allow")
			.map(|row| row.1.clone())
			.collect();
		if admin::is_allowed(ip, &allowed) {
			return None;
		}
		rows.into_iter()
			.filter(|row| row.0 == "ban" && admin::ban_applies(&row.1, ip))
			.map(|(_, _, until, reason)| BanInfo {
				until_secs: until.max(0) as u64,
				reason,
			})
			.max_by_key(|info| info.until_secs)
	}

	async fn is_banned_inner(&self, subject: &str, now_secs: u64) -> Option<BanInfo> {
		if let Some(ip) = admin::ip_of_subject(subject) {
			return self.is_ip_banned(ip, now_secs).await;
		}
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

	/// A success drops the failure history and the spent ban row of
	/// `subject`, but never an active ban: a ban stays in force until its
	/// `until`, whoever signs in meanwhile. The check and the deletes run
	/// under the same per-subject lock as [`Self::record_failure_inner`], so
	/// a failure that trips the ban cannot slip between them.
	async fn clear_success_inner(&self, subject: &str, now_secs: u64) {
		let result = async {
			let mut tx = self.pool.begin().await?;
			lock_subject(&mut tx, subject).await?;
			let active: Option<(i32,)> = sqlx::query_as(
				"SELECT 1 FROM auth_ban WHERE subject = $1 AND until > to_timestamp($2)",
			)
			.bind(subject)
			.bind(now_secs as i64)
			.fetch_optional(&mut *tx)
			.await?;
			if active.is_none() {
				sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
					.bind(subject)
					.execute(&mut *tx)
					.await?;
				sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
					.bind(subject)
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

	async fn sweep_inner(&self, now_secs: u64) {
		let horizon = now_secs.saturating_sub(24 * 60 * 60);
		// The bypass list uses its own window: a network the owner has
		// not signed in from for `known_network_window_secs` (30 days by
		// default) is no longer trusted, and the row is dropped here. The
		// 24h horizon above is for the failure log and the ban row, and
		// does not apply to the bypass list.
		let bypass_horizon = now_secs.saturating_sub(self.policy.known_network_window_secs);
		let result = async {
			sqlx::query("DELETE FROM auth_failure WHERE seen_at < to_timestamp($1)")
				.bind(horizon as i64)
				.execute(&self.pool)
				.await?;
			sqlx::query("DELETE FROM auth_ban WHERE until < to_timestamp($1)")
				.bind(horizon as i64)
				.execute(&self.pool)
				.await?;
			sqlx::query("DELETE FROM auth_known_network WHERE last_seen < $1")
				.bind(bypass_horizon as i64)
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
		// The pairs of this account go too. Account names are lowercase
		// letters, digits and hyphens, so the prefix holds no LIKE wildcard.
		let pairs = format!("pair:{}|%", account.to_ascii_lowercase());
		let result = async {
			let mut tx = self.pool.begin().await?;
			sqlx::query("DELETE FROM auth_ban WHERE subject = $1 OR subject LIKE $2")
				.bind(&subject)
				.bind(&pairs)
				.execute(&mut *tx)
				.await?;
			sqlx::query("DELETE FROM auth_failure WHERE subject = $1 OR subject LIKE $2")
				.bind(&subject)
				.bind(&pairs)
				.execute(&mut *tx)
				.await?;
			sqlx::query("DELETE FROM auth_known_network WHERE account = $1")
				.bind(account.to_ascii_lowercase())
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

	/// Whether the bypass list has a fresh row for `(account, network)`.
	/// Fail closed on database error: a missing row must not let a banned
	/// account in. The lookup is one round trip and the index on
	/// `(account, network)` covers it.
	async fn is_known_network_inner(&self, account: &str, ip: IpAddr, now_secs: u64) -> bool {
		let network = known_network_key(ip);
		let horizon = now_secs.saturating_sub(self.policy.known_network_window_secs);
		let row: Result<Option<(i64,)>, sqlx::Error> = sqlx::query_as(
			"SELECT last_seen FROM auth_known_network \
			 WHERE account = $1 AND network = $2 AND last_seen >= $3",
		)
		.bind(account.to_ascii_lowercase())
		.bind(&network)
		.bind(horizon as i64)
		.fetch_optional(&self.pool)
		.await;
		match row {
			Ok(Some(_)) => true,
			Ok(None) => false,
			Err(error) => {
				self.record_db_error(&error).await;
				// Fail closed: a database hiccup during a ban must not
				// become a pass. The pre-bypass-list behaviour is exactly
				// this refusal.
				false
			}
		}
	}

	/// Write `(account, network)` to the bypass list, throttled to one
	/// row per account per network per hour and capped per account at
	/// [`BanPolicy::known_network_max_per_account`]. The throttle lives
	/// in SQL: the `ON CONFLICT` UPDATE only fires when the prior row is
	/// older than the throttle, so a hot sign-in pattern does not keep
	/// writing. The cap eviction runs in the same transaction so the
	/// per-account row count never exceeds the ceiling.
	async fn record_known_network_inner(&self, account: &str, ip: IpAddr, now_secs: u64) {
		let network = known_network_key(ip);
		let account_lc = account.to_ascii_lowercase();
		let result = async {
			let mut tx = self.pool.begin().await?;
			// Throttled upsert: a sign-in inside the throttle window does
			// not write, so the latency-sensitive path stays at one
			// round trip per write. The WHERE clause on the UPDATE side
			// is what the throttle hangs on.
			sqlx::query(
				"INSERT INTO auth_known_network (account, network, last_seen, updated_at) \
				 VALUES ($1, $2, $3, to_timestamp($3)) \
				 ON CONFLICT (account, network) DO UPDATE SET \
				     last_seen = EXCLUDED.last_seen, \
				     updated_at = EXCLUDED.updated_at \
				 WHERE auth_known_network.last_seen <= $3 - $4",
			)
			.bind(&account_lc)
			.bind(&network)
			.bind(now_secs as i64)
			.bind(KNOWN_NETWORK_WRITE_THROTTLE_SECS as i64)
			.execute(&mut *tx)
			.await?;
			// Cap eviction: keep at most `known_network_max_per_account`
			// rows per account, evicting the oldest one when the count
			// is past the ceiling. The just-written row has the highest
			// `last_seen`, so once it gets rank 1 in a DESC ordering it
			// is guaranteed to survive; any row with rank above the cap
			// (the oldest) is dropped.
			let cap = self.policy.known_network_max_per_account as i64;
			sqlx::query(
				"DELETE FROM auth_known_network \
				 WHERE (account, network) IN ( \
				   SELECT account, network FROM ( \
				     SELECT account, network, \
				            row_number() OVER ( \
				              ORDER BY last_seen DESC \
				            ) AS rn \
				     FROM auth_known_network \
				     WHERE account = $1 \
				   ) ranked \
				   WHERE ranked.rn > $2 \
				 )",
			)
			.bind(&account_lc)
			.bind(cap)
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
