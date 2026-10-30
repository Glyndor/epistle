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

const SPAM: &str = "cheap pills offer discount prize";

/// Filler in front of the spam does not hide it: a message of one repeated
/// word and then the spam scores as the spam alone does.
#[tokio::test]
async fn spam_after_a_long_filler_still_scores_as_spam() {
	// Enough of both kinds for the corpus to be sure of its words.
	let trained: Vec<(&str, bool)> = TRAINED.iter().cycle().take(60).copied().collect();
	let Some((store, pool, scope)) = trained_store(&trained).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let filler = "zzfiller ".repeat(300 * 1024 / 9);
	let long = format!("{filler}{SPAM}");
	let got = store.score(&scope, &long).await.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(got, reference(&trained, &format!("zzfiller {SPAM}")));
	assert!(got > 0.9, "the spam scored {got}");
}

/// What is in the middle of a long message is not read, the start and the
/// end are, and a message that was not read in full is never below 0.5.
#[tokio::test]
async fn a_long_message_is_scored_on_its_start_and_its_end() {
	let Some((store, pool, scope)) = trained_store(&TRAINED).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let head = "agenda budget review ";
	let tail = " lunch design team friday";
	let filler = "filler ".repeat(40 * 1024);
	// Clean at both ends, spam in the middle: only the floor shows.
	let middle = format!("{head}{filler}{SPAM}{filler}{tail}");
	let got_middle = store.score(&scope, &middle).await.expect("score");
	// Spam at the end is read.
	let at_the_end = format!("{head}{filler}{filler}{SPAM}");
	let got_end = store.score(&scope, &at_the_end).await.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(
		got_middle,
		reference(&TRAINED, &format!("{head}{tail}")).max(0.5)
	);
	assert_eq!(
		got_end,
		reference(&TRAINED, &format!("{head}filler {SPAM}")).max(0.5)
	);
}

/// More distinct words than the cap: the message is scored on a sample no
/// one can steer, and a clean-looking start does not make it clean.
#[tokio::test]
async fn a_message_with_a_pile_of_distinct_filler_is_never_scored_as_clean() {
	let Some((store, pool, scope)) = trained_store(&TRAINED).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let filler: String = (0..20_000).map(|n| format!("wd{n:07x} ")).collect();
	let long = format!("agenda budget review lunch design team {filler}");
	let got = store.score(&scope, &long).await.expect("score");
	let again = store.score(&scope, &long).await.expect("score again");
	cleanup(&pool, &scope).await;
	assert!(got >= 0.5, "a capped message scored {got}");
	assert_eq!(got, again, "the sample must be the same every time");
}

/// The words the sample keeps do not depend on where the sender put them:
/// the spam words first or last in a pile of filler give the same score.
#[tokio::test]
async fn the_sample_does_not_depend_on_the_order_of_the_words() {
	let trained: Vec<(&str, bool)> = TRAINED.iter().cycle().take(60).copied().collect();
	let Some((store, pool, scope)) = trained_store(&trained).await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let mut words: Vec<String> = (0..12_000).map(|n| format!("wd{n:07x}")).collect();
	words.extend(SPAM.split(' ').map(String::from));
	let spam_last = words.join(" ");
	words.reverse();
	let spam_first = words.join(" ");
	let a = store.score(&scope, &spam_last).await.expect("score");
	let b = store.score(&scope, &spam_first).await.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(a, b);
}
