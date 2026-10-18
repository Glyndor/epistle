//! The queue in front of the shared corpus, with a real database behind it.
//! Needs a PostgreSQL and only runs when `DATABASE_URL` is set.

use epistle::antispam::corpus::BayesStore;
use epistle::antispam::shared_training::{FINE_PENDING, TrainSource};
use epistle::config::DatabaseTls;
use sqlx::PgPool;

fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

async fn connect() -> Option<PgPool> {
	let url = std::env::var("DATABASE_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	Some(
		epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
			.await
			.expect("connect and migrate"),
	)
}

/// The spam and ham totals of `scope`, once they are `want` messages in all.
async fn totals_when(pool: &PgPool, scope: &str, want: i64) -> (i64, i64) {
	for _ in 0..200 {
		let row: Option<(i64, i64)> =
			sqlx::query_as("SELECT ham_messages, spam_messages FROM bayes_corpus WHERE scope = $1")
				.bind(scope)
				.fetch_optional(pool)
				.await
				.expect("totals");
		if let Some((ham, spam)) = row
			&& ham + spam >= want
		{
			return (ham, spam);
		}
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	panic!("the corpus never reached {want} messages");
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
async fn a_queued_message_reaches_the_corpus() {
	let Some(pool) = connect().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = format!("queued-{}", uuid::Uuid::now_v7().simple());
	let source = TrainSource::new(Some("192.0.2.1".parse().expect("ip")), Some("a.example"));

	assert!(store.submit_training(&source, &scope, b"cheap pills offer", true));

	let totals = totals_when(&pool, &scope, 1).await;
	cleanup(&pool, &scope).await;
	assert_eq!(totals, (0, 1));
}

#[tokio::test]
async fn one_source_flooding_the_server_gets_only_its_share_trained() {
	let Some(pool) = connect().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = format!("flood-{}", uuid::Uuid::now_v7().simple());
	let flooder = TrainSource::new(Some("192.0.2.66".parse().expect("ip")), None);
	let other = TrainSource::new(Some("192.0.2.67".parse().expect("ip")), None);

	// A synchronous burst: the workers cannot run until the test awaits, so
	// what is accepted is exactly the flooder's share of the queue.
	let accepted = (0..500)
		.filter(|_| store.submit_training(&flooder, &scope, b"buy now", true))
		.count();
	assert_eq!(accepted, FINE_PENDING as usize);
	assert!(
		store.submit_training(&other, &scope, b"meeting notes", false),
		"another source must still get in"
	);

	let totals = totals_when(&pool, &scope, accepted as i64 + 1).await;
	// Give a wrongly accepted job the time to show up.
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	let (ham, spam): (i64, i64) =
		sqlx::query_as("SELECT ham_messages, spam_messages FROM bayes_corpus WHERE scope = $1")
			.bind(&scope)
			.fetch_one(&pool)
			.await
			.expect("totals");
	cleanup(&pool, &scope).await;
	assert_eq!(totals.0 + totals.1, accepted as i64 + 1);
	assert_eq!((ham, spam), (1, accepted as i64));
}
