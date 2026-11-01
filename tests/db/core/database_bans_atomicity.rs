//! Live-database tests for two guarantees of the shared ban store under
//! hostile timing: a success never lifts a ban that is still in force, and
//! concurrent failures on one subject are counted and struck atomically.
//! They need a real PostgreSQL and only run when `DATABASE_URL` is set, like
//! `tests/db/core/database_bans.rs`.

use std::sync::Arc;

use epistle::antispam::bans::{BanPolicy, BanStore, PgBanStore};
use epistle::config::DatabaseTls;

fn policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60 * 60,
		known_network_max_per_account: 32,
	}
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// A subject no other test or stale row shares.
fn fresh_subject() -> String {
	format!("ip:race-{}", uuid::Uuid::now_v7())
}

async fn connect() -> Option<(sqlx::PgPool, Arc<PgBanStore>)> {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set");
		return None;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 32, None)
		.await
		.expect("connect and migrate");
	let store = Arc::new(PgBanStore::with_policy(pool.clone(), None, policy()));
	Some((pool, store))
}

async fn failures(pool: &sqlx::PgPool, subject: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM auth_failure WHERE subject = $1")
		.bind(subject)
		.fetch_one(pool)
		.await
		.expect("count failures")
}

async fn ban_rows(pool: &sqlx::PgPool, subject: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM auth_ban WHERE subject = $1")
		.bind(subject)
		.fetch_one(pool)
		.await
		.expect("count bans")
}

async fn strikes(pool: &sqlx::PgPool, subject: &str) -> Option<i32> {
	sqlx::query_scalar("SELECT strikes FROM auth_ban WHERE subject = $1")
		.bind(subject)
		.fetch_optional(pool)
		.await
		.expect("read strikes")
}

async fn forget(pool: &sqlx::PgPool, subject: &str) {
	sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
		.bind(subject)
		.execute(pool)
		.await
		.expect("forget failures");
	sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
		.bind(subject)
		.execute(pool)
		.await
		.expect("forget ban");
}

/// Fire `times` failures on `subject` at once and wait for all of them.
async fn fail_together(store: &Arc<PgBanStore>, subject: &str, times: usize, at: u64) {
	let mut tasks = Vec::new();
	for _ in 0..times {
		let store = Arc::clone(store);
		let subject = subject.to_string();
		tasks.push(tokio::spawn(async move {
			store.record_failure(&subject, "smtp", at).await;
		}));
	}
	for task in tasks {
		task.await.expect("failure task");
	}
}

#[tokio::test]
async fn a_success_does_not_lift_a_ban_still_in_force() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let subject = fresh_subject();
	let t = now();
	for _ in 0..5 {
		store.record_failure(&subject, "smtp", t).await;
	}
	assert!(store.is_banned(&subject, t).await.is_some());

	store.clear_success(&subject, t).await;

	assert!(
		store.is_banned(&subject, t).await.is_some(),
		"a success must not lift a ban that is still in force"
	);
	assert_eq!(
		failures(&pool, &subject).await,
		5,
		"the failures behind an active ban must stay"
	);
	forget(&pool, &subject).await;
}

#[tokio::test]
async fn a_success_after_the_ban_expired_clears_the_row_and_the_failures() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let subject = fresh_subject();
	let t = now();
	for _ in 0..5 {
		store.record_failure(&subject, "smtp", t).await;
	}
	let after = t + policy().base_secs + 1;

	store.clear_success(&subject, after).await;

	assert_eq!(ban_rows(&pool, &subject).await, 0);
	assert_eq!(failures(&pool, &subject).await, 0);
	forget(&pool, &subject).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failures_reaching_the_threshold_still_ban() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	// Several rounds, each on a subject of its own: a lost count is a race,
	// and one clean round proves nothing.
	for _ in 0..20 {
		let subject = fresh_subject();
		let t = now();
		fail_together(&store, &subject, 5, t).await;
		assert_eq!(failures(&pool, &subject).await, 5);
		assert!(
			store.is_banned(&subject, t).await.is_some(),
			"five failures at once must ban, however they interleave"
		);
		forget(&pool, &subject).await;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failures_past_the_threshold_each_add_a_strike() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	for _ in 0..20 {
		let subject = fresh_subject();
		let t = now();
		// Four failures leave the subject one short of a ban; the next six
		// all count at or over the threshold, so each one is a strike.
		for _ in 0..4 {
			store.record_failure(&subject, "smtp", t).await;
		}
		assert!(store.is_banned(&subject, t).await.is_none());
		fail_together(&store, &subject, 6, t).await;
		assert_eq!(
			strikes(&pool, &subject).await,
			Some(6),
			"each concurrent failure over the threshold is one strike"
		);
		forget(&pool, &subject).await;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_success_racing_the_tripping_failure_cannot_erase_the_ban() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	for _ in 0..20 {
		let subject = fresh_subject();
		let t = now();
		for _ in 0..4 {
			store.record_failure(&subject, "smtp", t).await;
		}
		let failing = {
			let (store, subject) = (Arc::clone(&store), subject.clone());
			tokio::spawn(async move { store.record_failure(&subject, "smtp", t).await })
		};
		let succeeding = {
			let (store, subject) = (Arc::clone(&store), subject.clone());
			tokio::spawn(async move { store.clear_success(&subject, t).await })
		};
		failing.await.expect("failure task");
		succeeding.await.expect("success task");
		// Either order is legal, but never "banned row gone while the
		// failures that earned it remain": the success either ran first and
		// cleared four failures, or after and left the ban alone.
		let banned = store.is_banned(&subject, t).await.is_some();
		let rows = failures(&pool, &subject).await;
		assert!(
			(banned && rows == 5) || (!banned && rows == 1),
			"inconsistent outcome: banned={banned}, failures={rows}"
		);
		forget(&pool, &subject).await;
	}
}
