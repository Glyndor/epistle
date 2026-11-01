//! `BayesStore::score_message`, the way the SMTP server scores a message: the
//! raw bytes, reduced to the text a person reads (see
//! `epistle::antispam::scoring_text`). Needs a PostgreSQL and skips without
//! `DATABASE_URL`.

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

const TRAINED: [(&str, bool); 6] = [
	("cheap pills online pharmacy discount offer", true),
	("winner lottery prize claim offer today", true),
	("cheap watches discount replica offer", true),
	("meeting agenda for the quarterly budget review", false),
	("lunch on friday with the design team", false),
	("budget review notes and the agenda attached", false),
];

const SPAM: &str = "cheap pills offer discount prize";
const HAM: &str = "agenda budget review lunch design team";

/// A store trained on enough of both kinds for the corpus to be sure.
async fn store() -> Option<(BayesStore, sqlx::PgPool, String)> {
	let url = std::env::var("DATABASE_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	let pool = epistle::db::connect(&url, DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	let store = BayesStore::with_key(pool.clone(), fixture_key());
	let scope = format!("message-{}", uuid::Uuid::now_v7().simple());
	for (text, spam) in TRAINED.iter().cycle().take(60) {
		store.train(&scope, text, *spam).await.expect("train");
	}
	Some((store, pool, scope))
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

/// What the classifier gives for all the words of `text`, from the plain words.
fn reference(text: &str) -> f64 {
	let mut counts: HashMap<String, TokenCounts> = HashMap::new();
	let mut corpus = Corpus::default();
	for (message, spam) in TRAINED.iter().cycle().take(60) {
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

fn plain(body: &str) -> Vec<u8> {
	format!("From: a@example.org\r\nSubject: hello\r\n\r\n{body}\r\n").into_bytes()
}

/// A text part and an attachment of `blob` bytes of base64 that does not repeat.
fn with_attachment(body: &str, blob: usize) -> Vec<u8> {
	let mut state = 0x2545_f491_4f6c_dd1du64;
	let mut encoded = String::with_capacity(blob + blob / 76 + 2);
	for index in 0..blob {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		encoded.push(alphabet[(state % 64) as usize] as char);
		if index % 76 == 75 {
			encoded.push('\n');
		}
	}
	format!(
		"From: a@example.org\r\nSubject: hello\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=\"bb\"\r\n\r\n\
		 --bb\r\nContent-Type: text/plain\r\n\r\n{body}\r\n\
		 --bb\r\nContent-Type: application/pdf\r\n\
		 Content-Disposition: attachment; filename=\"a.pdf\"\r\n\
		 Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--bb--\r\n"
	)
	.into_bytes()
}

fn rare_words(count: usize) -> String {
	(0..count).map(|n| format!("rw{n:07x} ")).collect()
}

#[tokio::test]
async fn a_message_under_the_bounds_scores_on_all_its_words_as_before() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	for body in [
		SPAM,
		HAM,
		"cheap agenda pills review offer lunch",
		"nothing zzqx",
	] {
		let raw = plain(body);
		let got = store.score_message(&scope, &raw).await.expect("score");
		let expected = reference(&String::from_utf8_lossy(&raw));
		assert_eq!(got, expected, "the score of {body:?} changed");
	}
	cleanup(&pool, &scope).await;
}

#[tokio::test]
async fn a_legitimate_message_with_a_big_attachment_scores_as_without_it() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let small = store
		.score_message(&scope, &with_attachment(HAM, 1000))
		.await
		.expect("score");
	let large = store
		.score_message(&scope, &with_attachment(HAM, 300_000))
		.await
		.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(large, small);
	assert!(large < 0.5, "a message with an attachment scored {large}");
}

#[tokio::test]
async fn spam_hidden_behind_a_big_attachment_still_scores_as_spam() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let small = store
		.score_message(&scope, &with_attachment(SPAM, 1000))
		.await
		.expect("score");
	let large = store
		.score_message(&scope, &with_attachment(SPAM, 3_000_000))
		.await
		.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(large, small);
	assert!(large > 0.95, "the spam scored {large}");
}

#[tokio::test]
async fn a_text_part_sent_as_base64_is_scored_on_what_it_says() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let raw = b"From: a@example.org\r\nSubject: hello\r\nContent-Type: text/plain\r\n\
		Content-Transfer-Encoding: base64\r\n\r\nY2hlYXAgcGlsbHMgb2ZmZXIgZGlzY291bnQgcHJpemU=\r\n";
	let got = store.score_message(&scope, raw).await.expect("score");
	cleanup(&pool, &scope).await;
	assert!(got > 0.95, "base64 spam scored {got}");
}

#[tokio::test]
async fn spam_in_the_middle_of_filler_that_is_not_words_is_read_in_full() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	// Clean at both ends and spam only in the middle of 600 KiB of nothing.
	let filler = format!("{}{}", " ".repeat(400 * 1024), "x ".repeat(200 * 1024));
	let without = store
		.score_message(&scope, &plain(&format!("{HAM} {SPAM} {HAM}")))
		.await
		.expect("score");
	let hidden = store
		.score_message(
			&scope,
			&plain(&format!("{HAM} {filler} {SPAM} {filler} {HAM}")),
		)
		.await
		.expect("score");
	cleanup(&pool, &scope).await;
	assert_eq!(hidden, without, "filler changed the score");
}

#[tokio::test]
async fn filler_made_of_rare_words_does_not_dilute_spam() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let alone = store
		.score_message(&scope, &plain(SPAM))
		.await
		.expect("score");
	for body in [
		format!("{SPAM} {}", rare_words(60_000)),
		format!("{} {SPAM}", rare_words(60_000)),
		format!("{SPAM} {}", "word ".repeat(55_000)),
	] {
		let got = store
			.score_message(&scope, &plain(&body))
			.await
			.expect("score");
		assert!(
			got >= 0.95 && (got - alone).abs() < 1e-6,
			"filler changed {alone} to {got}"
		);
	}
	cleanup(&pool, &scope).await;
}

#[tokio::test]
async fn a_message_that_does_not_fit_in_the_window_is_never_clean() {
	let Some((store, pool, scope)) = store().await else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	// Few distinct words, but more text than the window holds: the middle is
	// not read, and spam can sit in it.
	let body = format!("{HAM} {}", "hello ".repeat(100_000));
	let got = store
		.score_message(&scope, &plain(&body))
		.await
		.expect("score");
	cleanup(&pool, &scope).await;
	assert!(
		got >= 0.5,
		"a message that was not read in full scored {got}"
	);
}
