//! Live-database tests for the shared ban store. They need a real
//! PostgreSQL and only run when `DATABASE_URL` is set (the `Database` CI
//! workflow provides one); otherwise they skip so the default test run
//! needs no database.
//!
//! The unit tests in `src/antispam/bans_tests.rs` cover the same
//! behaviour through an in-memory `FakeBanStore`. These cases are the
//! PostgreSQL counterpart: the SQL projection, the upsert that drives
//! the backoff, the sweep horizon, and the fail-open contract under
//! `pool.close()`. The CI database is a container on the runner's
//! loopback with no TLS, which is exactly the case `DatabaseTls::Insecure`
//! exists for.

use epistle::antispam::bans::{BanInfo, BanPolicy, BanStore, PgBanStore};
use epistle::config::DatabaseTls;

/// The connection URL, or `None` when no database is configured for this run.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A fresh subject name per test invocation so reruns against a
/// persistent database stay isolated. The names start with the same
/// prefix so a stale row left by a crashed previous run is obvious in
/// the table.
fn fresh_subject(prefix: &str) -> String {
	format!("{prefix}-{}", uuid::Uuid::now_v7())
}

fn shrink_policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
	}
}

async fn clean_subject(pool: &sqlx::PgPool, subject: &str) {
	sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
		.bind(subject)
		.execute(pool)
		.await
		.expect("clear auth_failure");
	sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
		.bind(subject)
		.execute(pool)
		.await
		.expect("clear auth_ban");
}

#[tokio::test]
async fn five_failures_in_the_window_ban_the_subject() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	// Four failures are below the threshold; the subject stays clean.
	for _ in 0..4 {
		store.record_failure(&subject, "smtp", now).await;
	}
	assert!(
		store.is_banned(&subject, now).await.is_none(),
		"four failures must not trip a ban"
	);
	clean_subject(&pool, &subject).await;

	// The fifth trips it.
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	for _ in 0..5 {
		store.record_failure(&subject, "smtp", now).await;
	}
	let info = store
		.is_banned(&subject, now)
		.await
		.expect("banned after five failures");
	assert!(
		info.until_secs > now,
		"ban must extend past the recording time"
	);
	assert_eq!(info.reason, "5 failed authentications in 60 seconds");
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn four_do_not() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	for _ in 0..4 {
		store.record_failure(&subject, "smtp", now).await;
	}
	assert!(store.is_banned(&subject, now).await.is_none());
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn a_second_ban_doubles_the_duration() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// First ban: 5 failures, base duration (60s in the shrunk policy).
	for _ in 0..5 {
		store.record_failure(&subject, "smtp", now).await;
	}
	let first = store
		.is_banned(&subject, now)
		.await
		.expect("banned after five failures");
	assert_eq!(first.until_secs - now, 60);
	// One more failure re-upserts the ban with the doubled duration.
	store.record_failure(&subject, "smtp", now).await;
	let second = store
		.is_banned(&subject, now)
		.await
		.expect("banned after six failures");
	assert_eq!(second.until_secs - now, 120);
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn the_backoff_caps_at_24h() {
	// The production policy's 24h cap is enforced by the SQL too:
	// PgBanStore::with_policy shares the duration_for helper. A
	// doubled duration that exceeds max_secs must clamp to max_secs
	// rather than overflow.
	let policy = BanPolicy::default();
	let strikes = 20u32;
	let duration = policy.duration_for(strikes);
	assert_eq!(duration.as_secs(), policy.max_secs);
	// And in the live database: a subject that keeps tripping bans
	// past the cap holds at max_secs, never longer.
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::new(pool.clone(), None);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// Drive enough failures to take the strikes counter well past
	// the cap. The exact count is the production threshold (5) plus
	// enough to push the doubling past the cap.
	for _ in 0..policy.threshold + 5 {
		store.record_failure(&subject, "smtp", now).await;
	}
	let info = store.is_banned(&subject, now).await.expect("banned");
	assert_eq!(info.until_secs - now, policy.max_secs);
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn success_clears_the_ban_and_the_failures() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	for _ in 0..5 {
		store.record_failure(&subject, "smtp", now).await;
	}
	assert!(store.is_banned(&subject, now).await.is_some());
	store.clear_success(&subject).await;
	assert!(store.is_banned(&subject, now).await.is_none());
	let failures: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_failure WHERE subject = $1")
		.bind(&subject)
		.fetch_one(&pool)
		.await
		.expect("count failures");
	assert_eq!(failures, 0, "clear_success must drop the failures too");
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn sweep_forgets_old_rows() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::with_policy(pool.clone(), None, shrink_policy());
	let old: u64 = 1_700_000_000;
	store.record_failure(&subject, "smtp", old).await;
	// 25 hours later the sweep drops rows older than 24h.
	store.sweep(old + 25 * 60 * 60).await;
	let failures: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_failure WHERE subject = $1")
		.bind(&subject)
		.fetch_one(&pool)
		.await
		.expect("count failures");
	assert_eq!(failures, 0, "sweep must drop failures older than 24h");
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn a_database_error_is_not_a_ban() {
	// The fail-open contract: a closed pool must read as "not banned"
	// rather than propagate the error. We close the pool to force
	// every subsequent query to error out.
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	pool.close().await;
	let store = PgBanStore::new(pool.clone(), None);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	assert!(
		store.is_banned("ip:203.0.113.99", now).await.is_none(),
		"a database error must read as not banned"
	);
}

/// A `BanInfo` round-trips through the schema without the reason being
/// truncated or re-encoded. Used as a sanity check that the SQL
/// projection matches the `BanInfo` Rust type the directory consumes.
#[tokio::test]
async fn ban_info_roundtrips_through_the_schema() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let until = now + 90;
	sqlx::query(
		"INSERT INTO auth_ban (subject, strikes, until, reason, created_at, updated_at) \
		 VALUES ($1, $2, to_timestamp($3), $4, to_timestamp($5), to_timestamp($5))",
	)
	.bind(&subject)
	.bind(1_i32)
	.bind(until as i64)
	.bind("5 failed authentications in 900 seconds")
	.bind(now as i64)
	.execute(&pool)
	.await
	.expect("insert ban");

	let store = PgBanStore::new(pool.clone(), None);
	let info: BanInfo = store.is_banned(&subject, now).await.expect("banned");
	assert_eq!(info.until_secs, until);
	assert_eq!(info.reason, "5 failed authentications in 900 seconds");
	clean_subject(&pool, &subject).await;
}
