//! Database integration tests. These need a real PostgreSQL and only run when
//! `DATABASE_URL` is set (the `Database` CI workflow provides one); otherwise
//! they skip so the default test run needs no database.

/// The connection URL, or `None` when no database is configured for this run.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

#[tokio::test]
async fn migrations_apply_and_reputation_roundtrips() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};

	let pool = mail::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	// A fresh insert and read-back exercises the migrated schema end to end.
	let id = uuid::Uuid::now_v7();
	sqlx::query("INSERT INTO reputation (id, scope, value, ham_count) VALUES ($1, $2, $3, $4)")
		.bind(id)
		.bind("domain")
		.bind("example.org")
		.bind(3_i64)
		.execute(&pool)
		.await
		.expect("insert reputation");

	let (scope, ham): (String, i64) =
		sqlx::query_as("SELECT scope, ham_count FROM reputation WHERE id = $1")
			.bind(id)
			.fetch_one(&pool)
			.await
			.expect("read reputation");
	assert_eq!(scope, "domain");
	assert_eq!(ham, 3);

	// Clean up so reruns against a persistent database stay deterministic.
	sqlx::query("DELETE FROM reputation WHERE id = $1")
		.bind(id)
		.execute(&pool)
		.await
		.expect("cleanup");
}

#[tokio::test]
async fn reputation_record_accumulates_and_judges() {
	use mail::antispam::reputation::{self, Scope, Verdict};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = mail::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	let value = format!("rep-{}.example", uuid::Uuid::now_v7());

	// No history yet.
	assert!(
		reputation::lookup(&pool, Scope::Domain, &value)
			.await
			.expect("lookup")
			.is_none()
	);

	// Four ham observations, one spam: accumulates and reads back as trusted.
	for _ in 0..4 {
		reputation::record(&pool, Scope::Domain, &value, false)
			.await
			.expect("record ham");
	}
	reputation::record(&pool, Scope::Domain, &value, true)
		.await
		.expect("record spam");

	let score = reputation::lookup(&pool, Scope::Domain, &value)
		.await
		.expect("lookup")
		.expect("has history");
	assert_eq!(score.ham, 4);
	assert_eq!(score.spam, 1);
	assert_eq!(score.verdict(), Verdict::Trusted);

	sqlx::query("DELETE FROM reputation WHERE scope = 'domain' AND value = $1")
		.bind(&value)
		.execute(&pool)
		.await
		.expect("cleanup");
}

#[tokio::test]
async fn reputation_screen_maps_verdicts() {
	use mail::antispam::reputation::{self, Scope, Screen};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = mail::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	// Unknown identity: first-time.
	let fresh = format!("screen-{}.example", uuid::Uuid::now_v7());
	assert_eq!(
		reputation::screen(&pool, Scope::Domain, &fresh).await,
		Screen::FirstTime
	);

	// Spam-heavy identity: rejected.
	let bad = format!("bad-{}.example", uuid::Uuid::now_v7());
	for _ in 0..5 {
		reputation::record(&pool, Scope::Domain, &bad, true)
			.await
			.expect("record spam");
	}
	assert_eq!(
		reputation::screen(&pool, Scope::Domain, &bad).await,
		Screen::Reject
	);

	sqlx::query("DELETE FROM reputation WHERE value = $1")
		.bind(&bad)
		.execute(&pool)
		.await
		.expect("cleanup");
}
