//! Helpers shared by the learning tests that need a real PostgreSQL.

#![allow(dead_code)]

use epistle::antispam::corpus::BayesStore;
use epistle::config::DatabaseTls;
use sqlx::PgPool;

pub fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A 32-byte key minted at run time, so no literal reaches `with_key`.
pub fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

/// An account name no other test or earlier run uses.
pub fn fresh_account() -> String {
	format!("learn-{}", uuid::Uuid::now_v7().simple())
}

pub async fn connect() -> Option<(PgPool, BayesStore)> {
	let url = database_url().or_else(|| {
		eprintln!("skipping: DATABASE_URL not set");
		None
	})?;
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	Some((pool, store))
}

pub const SPAM: &[u8] = b"Subject: cheap pills\r\n\r\nbuy cheap pills discount viagra now\r\n";
pub const OTHER: &[u8] = b"Subject: agenda\r\n\r\nmeeting notes agenda project review\r\n";

/// (ham, spam) sums over every token row of the scope, and the row count.
pub async fn token_sums(pool: &PgPool, scope: &str) -> (i64, i64, i64) {
	sqlx::query_as(
		"SELECT COALESCE(SUM(ham_count), 0)::bigint, COALESCE(SUM(spam_count), 0)::bigint, \
		 COUNT(*) FROM bayes_token WHERE scope = $1",
	)
	.bind(scope)
	.fetch_one(pool)
	.await
	.expect("token sums")
}

pub async fn totals(store: &BayesStore, scope: &str) -> (u64, u64) {
	let corpus = store.corpus(scope).await.expect("corpus");
	(corpus.ham_messages, corpus.spam_messages)
}
