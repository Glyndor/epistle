//! Database integration tests for the persistent greylist store. These
//! need a real PostgreSQL, like the rest of the `tests/database*.rs`
//! integration tests, and only run when `DATABASE_URL` is set (the
//! `Database` CI workflow provides one); otherwise they skip so the
//! default test run needs no database.
//!
//! Split out of `tests/database.rs` because the bayes + directory tests
//! were already approaching the per-file line cap and the greylist
//! suite would have pushed it past the limit. The helpers the rest of
//! the database tests share (`database_url`) are duplicated here so
//! each integration binary stays self-contained: cargo builds every
//! `tests/database*.rs` as a separate crate, so `common/` does not
//! bleed across them.

use epistle::config::DatabaseTls;

/// The connection URL, or `None` when no database is configured for this run.
/// Mirrors the helper in `tests/database.rs`; cargo builds the two as
/// independent binaries, so duplication is the cleanest path.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// Pre-fab triplet pointing at deterministic test values. The literal
/// sender and recipient host names keep the key obviously test-only, so
/// a stray debug log cannot be mistaken for a real sender.
/// Each test owns its triplet. The tests in this file run in parallel against
/// one database, so a shared key let one test's cleanup delete the row
/// another was asserting on.
fn greylist_triplet(recipient: &'static str) -> epistle::antispam::greylist::Triplet<'static> {
	epistle::antispam::greylist::Triplet {
		client_ip: "192.0.2.10".parse().expect("ip"),
		sender: "Sender@Example.org",
		recipient,
	}
}

/// Timestamps for the tests that do not sweep. The sweep test deletes every
/// row first seen before `10_000 - 3600`, across the whole table and while the
/// other tests run, so they record their triplets well above that horizon.
const BASE: u64 = 1_000_000;

/// The PostgreSQL store enforces the same decision logic the memory
/// store does: first sighting defers, a retry before the delay defers,
/// a retry past the delay accepts. The test stores one triplet and
/// asserts the three observable outcomes through `decide`, so a
/// regression in the `record`/`first_seen` plumbing fails here rather
/// than in production.
#[tokio::test]
async fn greylist_sql_store_matches_the_decision_contract() {
	use epistle::antispam::greylist::{Decision, GreylistStore, decide};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = epistle::antispam::PgGreylistStore::new(pool.clone());

	let triplet = greylist_triplet("Contract@Example.net");
	let key = triplet.key();

	// Always start clean.
	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&key)
		.execute(&pool)
		.await
		.expect("cleanup");

	// First sighting at BASE: defer and remember.
	assert_eq!(decide(&store, &triplet, BASE, 60).await, Decision::Defer);
	assert_eq!(store.first_seen(&key).await, Ok(Some(BASE)));

	// Retry at BASE + 30: too soon, keep deferring. `first_seen` must NOT
	// advance (the `ON CONFLICT` path keeps the original).
	assert_eq!(
		decide(&store, &triplet, BASE + 30, 60).await,
		Decision::Defer
	);
	assert_eq!(store.first_seen(&key).await, Ok(Some(BASE)));

	// Retry at BASE + 60: past the delay, accept. The stored `first_seen`
	// still anchors the row.
	assert_eq!(
		decide(&store, &triplet, BASE + 60, 60).await,
		Decision::Accept
	);
	assert_eq!(store.first_seen(&key).await, Ok(Some(BASE)));

	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&key)
		.execute(&pool)
		.await
		.expect("cleanup");
}

/// The SQL sweep drops triplets older than the configured lifetime. The
/// test inserts a row whose `first_seen` is a lifetime ago and verifies
/// the row is gone afterward, alongside an in-window row that must
/// remain.
#[tokio::test]
async fn greylist_sql_sweep_drops_only_old_rows() {
	use epistle::antispam::greylist::GreylistStore;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = epistle::antispam::PgGreylistStore::new(pool.clone());

	// Two keys with deterministic prefixes so re-runs stay isolated.
	let old_key = format!("ip-test-old-{}", uuid::Uuid::now_v7());
	let young_key = format!("ip-test-young-{}", uuid::Uuid::now_v7());

	// Old: first_seen at 1_000, lifetime 3600 → 4_600+ is expired. The
	// sweep at now=10_000 must delete it.
	let old_key_clone = old_key.clone();
	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&old_key)
		.execute(&pool)
		.await
		.expect("pre-clean old");
	sqlx::query("INSERT INTO greylist_triplet (key, first_seen, last_seen) VALUES ($1, $2, $2)")
		.bind(&old_key)
		.bind(1_000_i64)
		.execute(&pool)
		.await
		.expect("insert old");

	// Young: first_seen at 9_000, well within the same 3_600 window
	// from `now = 10_000`. Must survive.
	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&young_key)
		.execute(&pool)
		.await
		.expect("pre-clean young");
	sqlx::query("INSERT INTO greylist_triplet (key, first_seen, last_seen) VALUES ($1, $2, $2)")
		.bind(&young_key)
		.bind(9_000_i64)
		.execute(&pool)
		.await
		.expect("insert young");

	store.sweep(10_000, 3600).await;

	assert_eq!(
		store.first_seen(&old_key_clone).await,
		Ok(None),
		"old triplet must be gone after the sweep"
	);
	assert_eq!(
		store.first_seen(&young_key).await,
		Ok(Some(9_000)),
		"young triplet must remain after the sweep"
	);

	sqlx::query("DELETE FROM greylist_triplet WHERE key IN ($1, $2)")
		.bind(&old_key)
		.bind(&young_key)
		.execute(&pool)
		.await
		.expect("cleanup");
}

/// Restart-survival regression: a triplet recorded in one store
/// instance must be seen as "already first seen" by a fresh instance.
/// The test instantiates `PgGreylistStore` twice over the same pool and
/// asserts the second one observes the row from the first.
#[tokio::test]
async fn greylist_sql_store_survives_a_restart() {
	use epistle::antispam::greylist::{Decision, GreylistStore, decide};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");

	let triplet = greylist_triplet("Restart@Example.net");
	let key = triplet.key();
	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&key)
		.execute(&pool)
		.await
		.expect("pre-clean");

	// Process A: record the first sighting.
	let store_a = epistle::antispam::PgGreylistStore::new(pool.clone());
	assert_eq!(decide(&store_a, &triplet, BASE, 60).await, Decision::Defer);
	drop(store_a);

	// Process B: a fresh handle observes the row recorded by A.
	let store_b = epistle::antispam::PgGreylistStore::new(pool.clone());
	assert_eq!(
		store_b.first_seen(&key).await,
		Ok(Some(BASE)),
		"a fresh store must observe the first sighting persisted by the previous one"
	);

	// A retry past the delay is accepted without re-deferral.
	assert_eq!(
		decide(&store_b, &triplet, BASE + 1_000, 60).await,
		Decision::Accept,
		"after a restart the same triplet must wait out the delay exactly once"
	);

	sqlx::query("DELETE FROM greylist_triplet WHERE key = $1")
		.bind(&key)
		.execute(&pool)
		.await
		.expect("cleanup");
}
