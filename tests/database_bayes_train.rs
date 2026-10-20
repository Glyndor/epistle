//! Database integration tests for `BayesStore::train`, the path that feeds
//! the shared corpus from mail any remote sender can send. They need a real
//! PostgreSQL and only run when `DATABASE_URL` is set; otherwise they skip.
//!
//! The bound on one message (a window of its text, a cap on distinct tokens)
//! and the order the rows are locked in are the properties pinned here. The
//! lock order is checked by holding one lock from the test and looking at
//! which others the operation under test took before it had to wait, so it
//! does not depend on timing. The helpers are duplicated from the other
//! `tests/database*.rs` files: cargo builds each as its own crate.

use epistle::antispam::corpus::BayesStore;
use epistle::config::DatabaseTls;
use sqlx::PgPool;

/// The most distinct tokens one message may add. The same figure the
/// per-account lessons are held to.
const TOKEN_CAP: i64 = 5000;

fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A key minted at run time, so no literal reaches `with_key`.
fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

async fn pool(url: &str) -> PgPool {
	epistle::db::connect(url, DatabaseTls::Insecure, 12, None)
		.await
		.expect("connect and migrate")
}

/// A scope no other test uses, so the tests share one database.
fn fresh_scope() -> String {
	format!("train-{}", uuid::Uuid::now_v7().simple())
}

/// `count` distinct words, each a valid token, in ascending or descending order.
fn words(count: usize, descending: bool) -> String {
	let mut all: Vec<String> = (0..count).map(|n| format!("wd{n:07x}")).collect();
	if descending {
		all.reverse();
	}
	all.join(" ")
}

async fn rows(pool: &PgPool, scope: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM bayes_token WHERE scope = $1")
		.bind(scope)
		.fetch_one(pool)
		.await
		.expect("count rows")
}

async fn cleanup(pool: &PgPool, scope: &str) {
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(scope)
		.execute(pool)
		.await
		.expect("cleanup tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(scope)
		.execute(pool)
		.await
		.expect("cleanup totals");
}

#[tokio::test]
async fn a_large_message_adds_at_most_the_token_cap() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = pool(&url).await;
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = fresh_scope();

	// 100 000 distinct words, about 1 MiB: the window cuts it first and the
	// cap cuts what is left.
	store
		.train(&scope, &words(100_000, false), true)
		.await
		.expect("train");

	let stored = rows(&pool, &scope).await;
	cleanup(&pool, &scope).await;
	assert!(
		stored <= TOKEN_CAP,
		"one message stored {stored} token rows, the cap is {TOKEN_CAP}"
	);
	assert!(stored > 0, "a message with tokens must store some");
}

#[tokio::test]
async fn the_start_and_the_end_of_a_long_text_are_trained_on() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = pool(&url).await;
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = fresh_scope();

	// A marker at each end of 300 KiB of one repeated word: filler in front
	// must not hide what comes after it.
	let text = format!(
		"headmarker {}tailmarkera tailmarkerb tailmarkerc",
		"filler ".repeat(300 * 1024 / 7)
	);
	store.train(&scope, &text, false).await.expect("train");

	let stored = rows(&pool, &scope).await;
	cleanup(&pool, &scope).await;
	assert_eq!(
		stored, 5,
		"the start, the filler and the three words of the end must be stored"
	);
}

/// A message with more words than the cap is cut down to the same words
/// whatever order the sender wrote them in: where they are put buys nothing.
#[tokio::test]
async fn which_words_are_kept_does_not_depend_on_their_order() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = pool(&url).await;
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let (forward, backward) = (fresh_scope(), fresh_scope());

	store
		.train(&forward, &words(20_000, false), true)
		.await
		.expect("train");
	store
		.train(&backward, &words(20_000, true), true)
		.await
		.expect("train");

	let kept = |scope: String| {
		let pool = pool.clone();
		async move {
			let tokens: Vec<String> = sqlx::query_scalar(
				r#"SELECT token FROM bayes_token WHERE scope = $1 ORDER BY token COLLATE "C""#,
			)
			.bind(scope)
			.fetch_all(&pool)
			.await
			.expect("tokens");
			tokens
		}
	};
	let (first, second) = (kept(forward.clone()).await, kept(backward.clone()).await);
	cleanup(&pool, &forward).await;
	cleanup(&pool, &backward).await;
	assert_eq!(first.len(), TOKEN_CAP as usize);
	assert!(first == second, "the words kept depend on their order");
}

#[tokio::test]
async fn counts_add_up_over_repeated_training() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = pool(&url).await;
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = fresh_scope();

	store
		.train(&scope, "alpha alpha beta", true)
		.await
		.expect("spam");
	store.train(&scope, "beta gamma", false).await.expect("ham");
	store
		.train(&scope, "beta gamma", false)
		.await
		.expect("ham again");

	let (ham, spam): (i64, i64) = sqlx::query_as(
		"SELECT COALESCE(sum(ham_count), 0)::bigint, COALESCE(sum(spam_count), 0)::bigint \
		 FROM bayes_token WHERE scope = $1",
	)
	.bind(&scope)
	.fetch_one(&pool)
	.await
	.expect("sums");
	let (ham_messages, spam_messages): (i64, i64) =
		sqlx::query_as("SELECT ham_messages, spam_messages FROM bayes_corpus WHERE scope = $1")
			.bind(&scope)
			.fetch_one(&pool)
			.await
			.expect("totals");
	let stored = rows(&pool, &scope).await;
	cleanup(&pool, &scope).await;
	// alpha and beta once each for the spam, beta and gamma twice each for the ham.
	assert_eq!((stored, spam, ham), (3, 2, 4));
	assert_eq!((ham_messages, spam_messages), (2, 1));
}

/// The lock-order tests wait on locks they hold themselves, so they run one
/// at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Whether another connection cannot lock the `bayes_token` row of `token`.
async fn token_locked(pool: &PgPool, scope: &str, token: &str) -> bool {
	let mut tx = pool.begin().await.expect("begin");
	let probe =
		sqlx::query("SELECT 1 FROM bayes_token WHERE scope = $1 AND token = $2 FOR UPDATE NOWAIT")
			.bind(scope)
			.bind(token)
			.fetch_optional(&mut *tx)
			.await;
	drop(tx);
	probe.is_err()
}

/// Whether another connection cannot lock the `bayes_corpus` row of `scope`.
async fn corpus_locked(pool: &PgPool, scope: &str) -> bool {
	let mut tx = pool.begin().await.expect("begin");
	let probe = sqlx::query("SELECT 1 FROM bayes_corpus WHERE scope = $1 FOR UPDATE NOWAIT")
		.bind(scope)
		.fetch_optional(&mut *tx)
		.await;
	drop(tx);
	probe.is_err()
}

/// The hashed tokens of `scope`, in the order the rows are written.
async fn tokens_in_order(pool: &PgPool, scope: &str) -> Vec<String> {
	sqlx::query_scalar(
		r#"SELECT token FROM bayes_token WHERE scope = $1 ORDER BY token COLLATE "C""#,
	)
	.bind(scope)
	.fetch_all(pool)
	.await
	.expect("tokens")
}

/// Wait until a statement starting with `prefix` is blocked on a lock.
async fn wait_for_blocked(pool: &PgPool, prefix: &'static str) {
	for _ in 0..100 {
		let blocked: i64 = sqlx::query_scalar(
			"SELECT count(*) FROM pg_stat_activity \
			 WHERE wait_event_type = 'Lock' AND query LIKE $1",
		)
		.bind(format!("{prefix}%"))
		.fetch_one(pool)
		.await
		.expect("activity");
		if blocked > 0 {
			return;
		}
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	panic!("no statement starting with {prefix:?} ever blocked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgetting_a_scope_takes_the_totals_before_the_tokens() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let _serial = SERIAL.lock().await;
	let pool = pool(&url).await;
	let key = fixture_key();
	let scope = fresh_scope();
	BayesStore::with_key(pool.clone(), key)
		.train(&scope, &words(50, false), true)
		.await
		.expect("seed");
	let token = tokens_in_order(&pool, &scope).await.remove(0);

	// Hold the totals row, as a training in another process does.
	let mut holder = pool.begin().await.expect("begin");
	sqlx::query("SELECT 1 FROM bayes_corpus WHERE scope = $1 FOR UPDATE")
		.bind(&scope)
		.fetch_one(&mut *holder)
		.await
		.expect("hold totals");
	let remover = BayesStore::with_key(pool.clone(), key);
	let removal = {
		let scope = scope.clone();
		tokio::spawn(async move { remover.forget_scope(&scope).await })
	};
	wait_for_blocked(&pool, "DELETE FROM bayes_corpus").await;
	let early = token_locked(&pool, &scope, &token).await;
	holder.commit().await.expect("release");
	removal.await.expect("join").expect("forget");
	cleanup(&pool, &scope).await;
	assert!(
		!early,
		"forget_scope locked token rows before it had the totals row"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn training_takes_the_totals_before_the_tokens() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let _serial = SERIAL.lock().await;
	let pool = pool(&url).await;
	let key = fixture_key();
	let scope = fresh_scope();
	let text = words(50, false);
	BayesStore::with_key(pool.clone(), key)
		.train(&scope, &text, true)
		.await
		.expect("seed");
	let token = tokens_in_order(&pool, &scope).await.remove(0);

	// Hold one token row, as a training in another process does.
	let mut holder = pool.begin().await.expect("begin");
	sqlx::query("SELECT 1 FROM bayes_token WHERE scope = $1 AND token = $2 FOR UPDATE")
		.bind(&scope)
		.bind(&token)
		.fetch_one(&mut *holder)
		.await
		.expect("hold token");
	let trainer = BayesStore::with_key(pool.clone(), key);
	let training = {
		let scope = scope.clone();
		tokio::spawn(async move { trainer.train(&scope, &text, false).await })
	};
	wait_for_blocked(&pool, "INSERT INTO bayes_token").await;
	let has_totals = corpus_locked(&pool, &scope).await;
	holder.commit().await.expect("release");
	training.await.expect("join").expect("train");
	cleanup(&pool, &scope).await;
	assert!(
		has_totals,
		"a training waiting on a token row must already hold the totals row"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn training_writes_token_rows_in_ascending_order() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let _serial = SERIAL.lock().await;
	let pool = pool(&url).await;
	let key = fixture_key();
	let scope = fresh_scope();
	let text = words(300, false);
	BayesStore::with_key(pool.clone(), key)
		.train(&scope, &text, true)
		.await
		.expect("seed");
	let ordered = tokens_in_order(&pool, &scope).await;
	let middle = ordered.len() / 2;

	// Hold the middle row: a training that writes in ascending order has
	// updated every row before it and none after it when it has to wait.
	let mut holder = pool.begin().await.expect("begin");
	sqlx::query("SELECT 1 FROM bayes_token WHERE scope = $1 AND token = $2 FOR UPDATE")
		.bind(&scope)
		.bind(&ordered[middle])
		.fetch_one(&mut *holder)
		.await
		.expect("hold token");
	let trainer = BayesStore::with_key(pool.clone(), key);
	let training = {
		let scope = scope.clone();
		tokio::spawn(async move { trainer.train(&scope, &text, false).await })
	};
	wait_for_blocked(&pool, "INSERT INTO bayes_token").await;
	let mut wrong = 0;
	for (index, token) in ordered.iter().enumerate() {
		if index == middle {
			continue;
		}
		if token_locked(&pool, &scope, token).await != (index < middle) {
			wrong += 1;
		}
	}
	holder.commit().await.expect("release");
	training.await.expect("join").expect("train");
	cleanup(&pool, &scope).await;
	assert_eq!(
		wrong,
		0,
		"{wrong} of {} rows were not locked in ascending token order",
		ordered.len()
	);
}
