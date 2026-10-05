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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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

/// Pure-function check on the policy's cap: assert the three strikes
/// around the boundary, computed from the policy's `base_secs` and
/// `max_secs` (not by walking `duration_for`, the function under test).
/// The boundary is the smallest `strikes` count at which the
/// unclamped `base * 2^(strikes-1)` reaches `max_secs`; the
/// `last_below_strikes` is one less and stays strictly below the cap.
/// Both the boundary strike and the next one must clamp to exactly
/// `max_secs` (not overshoot, not undershoot). A bug that clamps one
/// strike late (the boundary returns the unclamped value) fails the
/// boundary assertion; a bug that clamps to `max_secs + 1` instead of
/// `max_secs` also fails.
#[test]
fn the_backoff_clamps_at_the_boundary() {
	let policy = BanPolicy::default();
	let (last_below_strikes, boundary_strikes) = cap_boundary_strikes(&policy);
	// The last strike below the cap: base * 2^(n-1) is strictly less
	// than max_secs, so the policy returns it unchanged. The helper
	// must pick a count that is strictly below the cap, otherwise the
	// test asserts the wrong strike.
	let expected_last_below = policy
		.base_secs
		.saturating_mul(1u64 << last_below_strikes.saturating_sub(1));
	assert!(
		expected_last_below < policy.max_secs,
		"the helper must pick a last-below count that is strictly below the cap; \
		 got {expected_last_below} >= {} (policy: {policy:?})",
		policy.max_secs,
	);
	assert_eq!(
		policy.duration_for(last_below_strikes).as_secs(),
		expected_last_below,
		"the last strike below the cap must produce the unclamped duration (base * 2^(n-1))",
	);
	// The boundary strike: the first where base * 2^(n-1) >= max_secs.
	// The policy must clamp to exactly max_secs, not overshoot.
	assert_eq!(
		policy.duration_for(boundary_strikes).as_secs(),
		policy.max_secs,
		"the boundary strike must clamp to exactly the cap, not overshoot \
		 (a 'clamp one strike late' bug would return the unclamped value here)",
	);
	// The strike after the boundary: still clamped to max_secs.
	assert_eq!(
		policy.duration_for(boundary_strikes + 1).as_secs(),
		policy.max_secs,
		"the strike after the boundary must still be clamped to the cap",
	);
}

/// The two strikes that straddle the cap, computed from the policy's
/// `base_secs` and `max_secs` alone, never by walking `duration_for`,
/// the function the test is asserting on. Returns
/// `(last_below_strikes, boundary_strikes)`:
/// - `last_below_strikes` is the largest strikes count where
///   `base * 2^(last_below_strikes - 1) < max_secs` (the duration is
///   the unclamped value, strictly below the cap).
/// - `boundary_strikes` is `last_below_strikes + 1`, the first strikes
///   count where the unclamped value is at or above the cap, so the
///   policy clamps to exactly `max_secs`.
///
/// For the production policy (15 min base, 24 h cap) the answer is
/// `(7, 8)`: 15 min x 2^6 = 16 h is below the cap; 15 min x 2^7 = 32 h
/// is above and clamps. The loop never reads `duration_for` and never
/// reads `max_secs` before comparing it, so a future policy that
/// grows the base or shrinks the cap is still measured correctly.
/// The cap is `1u64 << 32` (4 GiB) of exp before the shift overflows
/// on a 64-bit target, well past any doubling chain the policy can
/// reach.
fn cap_boundary_strikes(policy: &BanPolicy) -> (u32, u32) {
	let mut exp: u32 = 0;
	loop {
		// `saturating_mul` is defensive: a base of `u64::MAX` would
		// otherwise panic on the `1u64 << exp` side; with the shift
		// it caps at u64::MAX and the comparison against max_secs
		// returns true (any value that saturates has overshot the
		// cap). The loop exits on the first `exp` where the
		// unclamped value reaches the cap.
		let unclamped = policy.base_secs.saturating_mul(1u64 << exp.min(63));
		if unclamped >= policy.max_secs {
			return (exp, exp + 1);
		}
		exp = exp.saturating_add(1);
		// Defensive: a policy with `base_secs = 0` never reaches
		// the cap. 64 is well past any doubling chain the policy
		// can express; anything beyond it is operator error.
		if exp >= 64 {
			panic!(
				"policy {policy:?} never reaches max_secs within 64 strikes; \
				 the test cannot pick a boundary"
			);
		}
	}
}

#[tokio::test]
async fn the_backoff_caps_at_24h() {
	// The production policy's 24h cap is enforced by the SQL too:
	// PgBanStore::with_policy shares the duration_for helper. A
	// doubled duration that exceeds max_secs must clamp to max_secs
	// rather than overflow.
	let policy = BanPolicy::default();
	let (last_below_strikes, boundary_strikes) = cap_boundary_strikes(&policy);
	// Sanity check on the helper before we trust the live database
	// arithmetic: the policy's documented cap is 24 h and the
	// production base is 15 min, so the boundary is at strikes=8.
	// Pinning the production numbers in code makes the live
	// expectations concrete and surfaces a future change to the
	// default that would otherwise silently move the boundary.
	assert_eq!(
		(policy.base_secs, policy.max_secs),
		(15 * 60, 24 * 60 * 60),
		"the production policy's base is 15 min and its cap is 24 h; \
		 changing these constants shifts the boundary strikes the test drives to"
	);
	assert_eq!(
		(last_below_strikes, boundary_strikes),
		(7, 8),
		"with the production base and cap the boundary strikes are (7, 8): \
		 15 min x 2^6 = 16 h is below the cap, 15 min x 2^7 = 32 h clamps to 24 h"
	);
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let subject = fresh_subject("ip");
	let store = PgBanStore::new(pool.clone(), None);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// Drive to each of the three boundary strikes plus one more
	// past, asserting the duration at each step. The first
	// `threshold` failures trip the first ban (strikes -> 1) and
	// each subsequent failure bumps the strike count by one, so
	// reaching strikes = `k` needs `threshold + (k - 1)` failures
	// (capped at zero for k = 0, not exercised here).
	let failures_for = |k: u32| policy.threshold.saturating_add(k - 1);
	// Strikes = `last_below_strikes` (7 with the production policy):
	// the duration is the unclamped value, strictly below the cap.
	let failures = failures_for(last_below_strikes);
	for _ in 0..failures {
		store.record_failure(&subject, "smtp", now).await;
	}
	let info = store
		.is_banned(&subject, now)
		.await
		.expect("banned at last_below");
	assert!(
		info.until_secs - now < policy.max_secs,
		"the last strike below the cap must be strictly below the cap; \
		 got {}, cap {}",
		info.until_secs - now,
		policy.max_secs,
	);
	// Strikes = `boundary_strikes` (8): the first clamped strike.
	store.record_failure(&subject, "smtp", now).await;
	let info = store
		.is_banned(&subject, now)
		.await
		.expect("banned at boundary");
	assert_eq!(
		info.until_secs - now,
		policy.max_secs,
		"the boundary strike must clamp to exactly the cap; \
		 a 'clamp one strike late' bug would return the unclamped value here"
	);
	// Strikes = `boundary_strikes + 1` (9): still clamped to the cap.
	store.record_failure(&subject, "smtp", now).await;
	let info = store
		.is_banned(&subject, now)
		.await
		.expect("banned past boundary");
	assert_eq!(
		info.until_secs - now,
		policy.max_secs,
		"the strike after the boundary must still be clamped to the cap"
	);
	// Strikes = `boundary_strikes + 2` (10): the cap holds further
	// out. The previous test only drove this far; keeping the
	// assertion makes the regression shape visible if a future
	// change moves the cap or removes the saturation.
	store.record_failure(&subject, "smtp", now).await;
	let info = store
		.is_banned(&subject, now)
		.await
		.expect("banned further past boundary");
	assert_eq!(
		info.until_secs - now,
		policy.max_secs,
		"a subject that keeps tripping bans past the cap must hold at max_secs \
		 ({}, {} h), never longer",
		policy.max_secs,
		policy.max_secs / 3600,
	);
	clean_subject(&pool, &subject).await;
}

#[tokio::test]
async fn success_clears_the_ban_and_the_failures() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
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
