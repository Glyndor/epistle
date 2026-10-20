//! How many statements training a batch of tokens takes. It needs a real
//! PostgreSQL and only runs when `DATABASE_URL` is set.
//!
//! sqlx logs each statement from the connection's own task, so the counter
//! is the process-wide subscriber; this file holds one test so nothing else
//! is counted.

use std::sync::atomic::{AtomicU64, Ordering};

use epistle::antispam::corpus::BayesStore;
use epistle::config::DatabaseTls;
use tracing_subscriber::layer::SubscriberExt;

static STATEMENTS: AtomicU64 = AtomicU64::new(0);

struct Statements;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Statements {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		if event.metadata().target() == "sqlx::query" {
			STATEMENTS.fetch_add(1, Ordering::Relaxed);
		}
	}
}

#[tokio::test]
async fn a_batch_of_tokens_is_written_in_a_few_statements() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	let store = BayesStore::with_key(pool.clone(), key);
	let scope = format!("statements-{}", uuid::Uuid::now_v7().simple());
	let text: String = (0..2000).map(|n| format!("wd{n:07x} ")).collect();

	tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Statements))
		.expect("the only subscriber of this process");
	let before = STATEMENTS.load(Ordering::Relaxed);
	store.train(&scope, &text, true).await.expect("train");
	let statements = STATEMENTS.load(Ordering::Relaxed) - before;

	let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM bayes_token WHERE scope = $1")
		.bind(&scope)
		.fetch_one(&pool)
		.await
		.expect("count");
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(&scope)
		.execute(&pool)
		.await
		.expect("cleanup");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(&scope)
		.execute(&pool)
		.await
		.expect("cleanup");
	assert_eq!(stored, 2000);
	assert!(
		(1..=6).contains(&statements),
		"2000 tokens took {statements} statements, expected a handful"
	);
}
