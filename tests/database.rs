//! Database integration tests. These need a real PostgreSQL and only run when
//! `DATABASE_URL` is set (the `Database` CI workflow provides one); otherwise
//! they skip so the default test run needs no database.

// The CI database is a container on the runner's loopback with no TLS, which
// is exactly the case `DatabaseTls::Insecure` exists for: a private network the
// operator vouches for. These tests exercise migrations, reputation and the
// Bayes corpora, not the transport, so forcing `Require` here would only make
// them fail on the absence of a certificate nobody issued. The ban store
// lives in `database_bans.rs` so the file stays under the per-file line cap.
use epistle::config::DatabaseTls;
use std::sync::LazyLock;

/// The connection URL, or `None` when no database is configured for this run.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// The password the SQL-sourced directory test hashes and later presents,
/// minted once per test binary from a UUIDv7. An integration test crate
/// cannot see `crate::smtp::auth::tests` (the source-of-truth helpers),
/// so the equivalent lives here, with the same shape and same goal: keep
/// a string literal out of every parameter named `password` so the
/// `rust/hard-coded-cryptographic-value` query has nothing to flag. The
/// companion helpers in `src/smtp/auth.rs` explain the rationale.
fn fixture_password() -> &'static str {
	static PASSWORD: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().simple().to_string());
	PASSWORD.as_str()
}

/// A password that is not [`fixture_password`], for the test that presents
/// the wrong one. Minted the same way so it cannot collide with the right
/// one by accident.
fn wrong_password() -> &'static str {
	static PASSWORD: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().simple().to_string());
	PASSWORD.as_str()
}

#[tokio::test]
async fn migrations_apply_and_reputation_roundtrips() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};

	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
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
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
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
async fn sql_directory_loads_resolves_and_authenticates() {
	use epistle::directory_store::{AccountStore, load_sql_accounts};
	use epistle::smtp::address::Address;
	use epistle::smtp::directory::Resolution;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");

	// A unique account so reruns against a persistent database stay isolated.
	let name = format!("dir-{}", uuid::Uuid::now_v7());
	let address = format!("{name}@example.org");
	let hash = epistle::smtp::auth::hash_password(fixture_password()).expect("hash");
	sqlx::query("INSERT INTO directory_account (name, password_hash) VALUES ($1, $2)")
		.bind(&name)
		.bind(&hash)
		.execute(&pool)
		.await
		.expect("insert account");
	sqlx::query("INSERT INTO directory_address (address, account) VALUES ($1, $2)")
		.bind(&address)
		.bind(&name)
		.execute(&pool)
		.await
		.expect("insert address");

	// Load via the async loader and feed the rows into a freshly built store.
	let accounts = load_sql_accounts(&pool).await.expect("load sql accounts");
	assert!(
		accounts.iter().any(|a| a.name == name),
		"loaded set contains the new account"
	);
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_sql_accounts(accounts);
	let directory = store.handle().current();

	assert_eq!(
		directory.resolve(&Address::parse(&address).expect("address")),
		Resolution::Account(name.clone())
	);
	assert_eq!(
		directory.authenticate(&address, fixture_password(), epistle::config::Protocol::Api),
		Some(name.clone())
	);
	assert_eq!(
		directory.authenticate(&address, wrong_password(), epistle::config::Protocol::Api),
		None
	);

	sqlx::query("DELETE FROM directory_account WHERE name = $1")
		.bind(&name)
		.execute(&pool)
		.await
		.expect("cleanup");
}

#[tokio::test]
async fn bayes_per_account_corpora_are_isolated() {
	use epistle::antispam::corpus;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
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

/// Below the [`MIN_TRUSTED_MESSAGES`] threshold the per-account score
/// falls back to the shared corpus: an account that has not trained
/// anything yet gets the server's general training rather than a
/// coin-flip. Trained by the trainer abstraction under the same trait
/// the production store implements.
#[tokio::test]
async fn score_falls_back_to_shared_below_the_threshold() {
	use epistle::antispam::corpus;
	use epistle::antispam::trainer::BayesTrainer;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");

	// A unique account so reruns stay isolated.
	let account = format!("fallback-{}", uuid::Uuid::now_v7());
	let store = corpus::BayesStore::with_key(pool.clone(), [11u8; 32]);

	// Train the shared scope with a marker so it has a real signal.
	for _ in 0..30 {
		store
			.train(corpus::SHARED, "xxmarker shared spam", true)
			.await
			.expect("train shared spam");
		store
			.train(corpus::SHARED, "ordinary ham body", false)
			.await
			.expect("train shared ham");
	}

	// `score_for_account` on an untrained scope returns the shared
	// corpus's score; the marker should look spammy.
	let shared_score = store
		.score(corpus::SHARED, "xxmarker")
		.await
		.expect("score shared");
	let account_score = store
		.score_for_account(&account, b"xxmarker")
		.await
		.expect("score for account");
	assert!(
		(account_score - shared_score).abs() < 1e-9,
		"account {account_score} vs shared {shared_score}"
	);

	// Cleanup.
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("clear account tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("clear account corpus");
	sqlx::query("DELETE FROM bayes_token WHERE scope = ''")
		.execute(&pool)
		.await
		.expect("clear shared tokens");
	sqlx::query("UPDATE bayes_corpus SET ham_messages = 0, spam_messages = 0 WHERE scope = ''")
		.execute(&pool)
		.await
		.expect("reset shared corpus");
}

/// At the [`MIN_TRUSTED_MESSAGES`] threshold on every side the
/// per-account score uses the account's scope (not the shared
/// fallback). The shared scope may have arbitrary prior counts from
/// concurrent tests; we use the account's own marker to assert that
/// the per-account classifier is consulted when trained.
#[tokio::test]
async fn score_uses_the_account_scope_at_the_threshold() {
	use epistle::antispam::corpus;
	use epistle::antispam::trainer::BayesTrainer;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");

	let account = format!("trained-{}", uuid::Uuid::now_v7());
	let store = corpus::BayesStore::with_key(pool.clone(), [12u8; 32]);

	// A unique marker that only this account's corpus has seen, so
	// the per-account scope is the only one that recognises it. The
	// shared corpus has no row for it, so `score` on the shared scope
	// falls through to a neutral 0.5 (one unknown token).
	let marker = format!("qqacct-{}", uuid::Uuid::now_v7());
	let spam_text = format!("{marker} very spammy content words here");
	let threshold: u64 = epistle::antispam::trainer::MIN_TRUSTED_MESSAGES;

	// Train ham to the threshold with the marker always present (the
	// `xxfiller` token pads the count without affecting the marker's
	// probability math).
	for _ in 0..threshold {
		store
			.train(&account, &format!("xxhamfiller-{marker}"), false)
			.await
			.expect("train account ham");
	}
	// And spam to the threshold, so the scope is at the boundary on
	// every side.
	for _ in 0..threshold {
		store
			.train(&account, &spam_text, true)
			.await
			.expect("train account spam");
	}
	let trained = store.is_trained(&account).await.expect("is_trained");
	assert!(trained, "both sides at the threshold: trained");

	// The per-account score for the marker is high (spam-only in this
	// account). The shared scope has not seen the marker and falls
	// through to neutral. The per-account scope wins.
	let account_score = store
		.score_for_account(&account, spam_text.as_bytes())
		.await
		.expect("score for account");
	let shared_score = store
		.score(corpus::SHARED, &spam_text)
		.await
		.expect("score shared");
	assert!(
		account_score > shared_score,
		"trained account {account_score} should score its marker higher than the shared scope {shared_score}"
	);
	assert!(account_score > 0.5, "trained account {account_score}");

	// Cleanup.
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("clear account tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("clear account corpus");
}

/// `forget_scope` removes every row under the named scope, returns the
/// number of token rows dropped, and leaves other scopes alone.
#[tokio::test]
async fn forget_scope_removes_only_that_scope() {
	use epistle::antispam::corpus;

	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5)
		.await
		.expect("connect and migrate");

	let store = corpus::BayesStore::with_key(pool.clone(), [13u8; 32]);
	let victim = format!("victim-{}", uuid::Uuid::now_v7());
	let bystander = format!("bystander-{}", uuid::Uuid::now_v7());

	// Train both scopes so each has rows to lose.
	for _ in 0..6 {
		store
			.train(&victim, "zzvictim token", true)
			.await
			.expect("train victim spam");
		store
			.train(&victim, "ordinary body", false)
			.await
			.expect("train victim ham");
		store
			.train(&bystander, "wwbystander token", true)
			.await
			.expect("train bystander spam");
		store
			.train(&bystander, "ordinary body", false)
			.await
			.expect("train bystander ham");
	}

	// Confirm both scopes have rows.
	let victim_corpus_before = store.corpus(&victim).await.expect("corpus victim");
	let bystander_corpus_before = store.corpus(&bystander).await.expect("corpus bystander");
	assert!(victim_corpus_before.spam_messages > 0);
	assert!(bystander_corpus_before.spam_messages > 0);

	// Drop the victim's scope. The bystander is untouched.
	let dropped = store.forget_scope(&victim).await.expect("forget victim");
	assert!(dropped > 0, "should have removed some token rows");

	let victim_corpus_after = store.corpus(&victim).await.expect("corpus victim after");
	let bystander_corpus_after = store
		.corpus(&bystander)
		.await
		.expect("corpus bystander after");
	assert_eq!(
		victim_corpus_after.ham_messages, 0,
		"victim ham must be gone"
	);
	assert_eq!(
		victim_corpus_after.spam_messages, 0,
		"victim spam must be gone"
	);
	assert_eq!(
		bystander_corpus_after.spam_messages, bystander_corpus_before.spam_messages,
		"bystander spam untouched"
	);

	// Cleanup the bystander so reruns stay isolated.
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(&bystander)
		.execute(&pool)
		.await
		.expect("clear bystander tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(&bystander)
		.execute(&pool)
		.await
		.expect("clear bystander corpus");
}
