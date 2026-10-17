//! `BayesStore::score` on a real PostgreSQL: a message under the bounds scores
//! exactly what the classifier gives for all of its tokens, and a message over
//! them is scored on its first window. Skips without `DATABASE_URL`.

use epistle::antispam::bayes::{self, Corpus, TokenCounts};
use epistle::antispam::corpus::BayesStore;
use epistle::config::DatabaseTls;
use std::collections::HashMap;

fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

async fn cleanup(pool: &sqlx::PgPool, scope: &str) {
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

/// What the classifier says for `text` given the messages trained, computed
/// from the plain tokens alone: no bounds, no hashing, no database.
fn reference(trained: &[(&str, bool)], text: &str) -> f64 {
	let mut counts: HashMap<String, TokenCounts> = HashMap::new();
	let mut corpus = Corpus::default();
	for (message, spam) in trained {
		if *spam {
			corpus.spam_messages += 1;
		} else {
			corpus.ham_messages += 1;
		}
		for token in bayes::tokenize(message) {
			let entry = counts.entry(token).or_default();
			if *spam {
				entry.spam += 1;
			} else {
				entry.ham += 1;
			}
		}
	}
	bayes::classify(
		&bayes::tokenize(text),
		|token| counts.get(token).copied().unwrap_or_default(),
		corpus,
	)
}

async fn trained_store(trained: &[(&str, bool)]) -> Option<(BayesStore, sqlx::PgPool, String)> {
	let url = std::env::var("DATABASE_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = format!("score-{}", uuid::Uuid::now_v7().simple());
	for (message, spam) in trained {
		store.train(&scope, message, *spam).await.expect("train");
	}
	Some((store, pool, scope))
}

const TRAINED: [(&str, bool); 6] = [
	("cheap pills online pharmacy discount offer", true),
	("winner lottery prize claim offer today", true),
	("cheap watches discount replica offer", true),
	("meeting agenda for the quarterly budget review", false),
	("lunch on friday with the design team", false),
	("budget review notes and the agenda attached", false),
];

#[tokio::test]
async fn a_short_message_scores_what_the_classifier_gives_for_all_its_tokens() {
	let Some((store, pool, scope)) = trained_store(&TRAINED).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	for text in [
		"cheap pills offer",
		"agenda for the budget review",
		"cheap agenda pills review offer lunch winner",
		"nothing here was ever trained zzqx",
		"",
	] {
		let got = store.score(&scope, text).await.expect("score");
		assert_eq!(got, reference(&TRAINED, text), "score of {text:?} changed");
	}
	cleanup(&pool, &scope).await;
}

#[tokio::test]
async fn a_message_past_the_window_is_scored_on_its_window() {
	let Some((store, pool, scope)) = trained_store(&TRAINED).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let head = "agenda budget review ";
	let filler = "x ".repeat(300 * 1024 / 2);
	// The spammy words come only after 256 KiB.
	let long = format!("{head}{filler}cheap pills offer discount prize");
	let got = store.score(&scope, &long).await.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(got, reference(&TRAINED, head));
}
