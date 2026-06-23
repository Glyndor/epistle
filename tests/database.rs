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

	let pool = epistle::db::connect(&url, 5)
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
	use epistle::antispam::reputation::{self, Scope, Verdict};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, 5)
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
	use epistle::antispam::reputation::{self, Scope, Screen};

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, 5)
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

#[tokio::test]
async fn bayes_corpus_trains_and_scores() {
	use epistle::antispam::corpus;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	let store = corpus::BayesStore::with_key(pool.clone(), [7u8; 32]);

	// Train: several spam messages with a marker token, several ham without.
	for _ in 0..6 {
		store
			.train(corpus::SHARED, "buy cheap viagra now discount", true)
			.await
			.expect("train spam");
		store
			.train(
				corpus::SHARED,
				"project meeting notes attached agenda",
				false,
			)
			.await
			.expect("train ham");
	}

	let spammy = store
		.score(corpus::SHARED, "viagra discount cheap")
		.await
		.expect("score");
	let hammy = store
		.score(corpus::SHARED, "meeting agenda notes")
		.await
		.expect("score");
	assert!(
		spammy > hammy,
		"spammy {spammy} should exceed hammy {hammy}"
	);
	assert!(spammy > 0.5, "spammy {spammy}");

	// Reset the shared corpus so reruns stay deterministic.
	sqlx::query("DELETE FROM bayes_token WHERE scope = ''")
		.execute(&pool)
		.await
		.expect("clear tokens");
	sqlx::query("UPDATE bayes_corpus SET ham_messages = 0, spam_messages = 0 WHERE scope = ''")
		.execute(&pool)
		.await
		.expect("reset corpus");
}

#[tokio::test]
async fn bayes_per_account_corpora_are_isolated() {
	use epistle::antispam::corpus;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	let store = corpus::BayesStore::with_key(pool.clone(), [9u8; 32]);

	// Alice trains a distinctive marker token as spam.
	for _ in 0..6 {
		store
			.train("alice@example.org", "zzzmarker special offer", true)
			.await
			.expect("train alice spam");
		store
			.train("alice@example.org", "ordinary message body text", false)
			.await
			.expect("train alice ham");
	}

	// Alice scores the marker as spammy; an untrained account and the shared
	// corpus are unaffected (per-account isolation).
	let alice = store
		.score("alice@example.org", "zzzmarker offer")
		.await
		.expect("score alice");
	let bob = store
		.score("bob@example.org", "zzzmarker offer")
		.await
		.expect("score bob");
	let shared = store
		.score(corpus::SHARED, "zzzmarker offer")
		.await
		.expect("score shared");
	assert!(alice > 0.5, "alice {alice}");
	// Alice's training raised the marker's score only for Alice; untrained
	// scopes are unaffected and an untrained account matches the untrained
	// shared corpus exactly (full isolation).
	assert!(
		alice > bob,
		"alice {alice} should exceed untrained bob {bob}"
	);
	assert!(
		(bob - shared).abs() < f64::EPSILON,
		"bob {bob} vs shared {shared}"
	);

	sqlx::query("DELETE FROM bayes_token WHERE scope = 'alice@example.org'")
		.execute(&pool)
		.await
		.expect("clear alice tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = 'alice@example.org'")
		.execute(&pool)
		.await
		.expect("clear alice corpus");
}
