//! Live-database tests that a user's lesson reads a message the way the SMTP
//! path does: the text a person reads, not the bytes that carry it, with the
//! same cap on tokens. Run only when `DATABASE_URL` is set.

mod learning_support;

use epistle::antispam::corpus::{BayesStore, MAX_TRAIN_TOKENS};
use epistle::antispam::learning::{LearnLimits, LearnOutcome, MAX_LEARN_TOKENS};
use learning_support::*;
use sqlx::PgPool;

const PARTS: &str = "From: a@example.test\r\nSubject: offer\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nbuy cheap pills discount viagra now\r\n";

/// `PARTS` with an attachment of `words` words that nobody wrote.
fn with_attachment(words: usize) -> Vec<u8> {
	use base64::Engine;
	let filler: String = (0..words).map(|n| format!("zz{n}qq ")).collect();
	let encoded = base64::engine::general_purpose::STANDARD.encode(filler);
	let mut message = String::from(PARTS);
	message.push_str(
		"--b1\r\nContent-Type: application/octet-stream\r\n\
		 Content-Transfer-Encoding: base64\r\n\r\n",
	);
	message.push_str(&encoded);
	message.push_str("\r\n--b1--\r\n");
	message.into_bytes()
}

/// The hashed tokens of a scope, sorted.
async fn tokens_of(pool: &PgPool, scope: &str) -> Vec<String> {
	sqlx::query_scalar("SELECT token FROM bayes_token WHERE scope = $1 ORDER BY token")
		.bind(scope)
		.fetch_all(pool)
		.await
		.expect("tokens")
}

#[tokio::test]
async fn an_attachment_is_not_learned_and_cannot_bury_the_words() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let (plain, heavy) = (fresh_account(), fresh_account());
	let mut bare = String::from(PARTS);
	bare.push_str("--b1--\r\n");
	store
		.learn(&plain, bare.as_bytes(), true)
		.await
		.expect("bare");
	store
		.learn(&heavy, &with_attachment(4_000), true)
		.await
		.expect("heavy");
	let (bare_rows, heavy_rows) = (
		tokens_of(&pool, &plain).await,
		tokens_of(&pool, &heavy).await,
	);
	assert!(!bare_rows.is_empty(), "the text part was learned");
	assert!(
		heavy_rows == bare_rows,
		"the base64 attachment added no token to the account"
	);
	let stats = store.learning_stats(&heavy).await.expect("stats");
	assert_eq!(stats.token_rows, i64::try_from(bare_rows.len()).unwrap());
	for scope in [&plain, &heavy] {
		store.forget_scope(scope).await.expect("cleanup");
	}
}

#[tokio::test]
async fn text_in_another_charset_is_read_by_the_lesson_as_by_the_server() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let latin1 = b"Subject: oferta\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9 gratis ahora\r\n".to_vec();
	let mut utf16 = b"Subject: oferta\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-16\r\n\r\n\xff\xfe".to_vec();
	for unit in "caf\u{e9} gratis ahora\r\n".encode_utf16() {
		utf16.extend_from_slice(&unit.to_le_bytes());
	}
	for (label, message) in [("latin-1", latin1), ("utf-16", utf16)] {
		let (taught, trained) = (fresh_account(), fresh_account());
		store.learn(&taught, &message, true).await.expect("learn");
		store
			.train_message(&trained, &message, true)
			.await
			.expect("train");
		let rows = tokens_of(&pool, &taught).await;
		assert!(!rows.is_empty(), "{label}: the text was learned");
		assert!(
			rows == tokens_of(&pool, &trained).await,
			"{label}: the lesson and the server read the same words"
		);
		for scope in [&taught, &trained] {
			store.forget_scope(scope).await.expect("cleanup");
		}
	}
}

#[tokio::test]
async fn a_lesson_and_the_shared_training_read_a_message_alike() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let (taught, trained) = (fresh_account(), fresh_account());
	let message = with_attachment(300);
	assert_eq!(
		store.learn(&taught, &message, true).await.expect("learn"),
		LearnOutcome::Learned
	);
	assert!(
		store
			.train_message(&trained, &message, true)
			.await
			.expect("train"),
		"the SMTP path read the message too"
	);
	assert!(
		tokens_of(&pool, &taught).await == tokens_of(&pool, &trained).await,
		"the same rows from the same message"
	);
	assert_eq!(
		totals(&store, &taught).await,
		totals(&store, &trained).await
	);
	for scope in [&taught, &trained] {
		store.forget_scope(scope).await.expect("cleanup");
	}
}

#[tokio::test]
async fn a_lesson_keeps_the_same_tokens_as_the_shared_training_when_the_cap_bites() {
	assert_eq!(
		MAX_LEARN_TOKENS, MAX_TRAIN_TOKENS,
		"a user's lesson and the server's own training share one cap"
	);
	let Some((pool, store)) = connect().await else {
		return;
	};
	let (taught, trained) = (fresh_account(), fresh_account());
	let words: String = (0..MAX_TRAIN_TOKENS + 800)
		.map(|n| format!("wq{n}x "))
		.collect();
	let message = format!("Subject: many words\r\n\r\n{words}\r\n");
	store
		.learn(&taught, message.as_bytes(), false)
		.await
		.expect("learn");
	store
		.train_message(&trained, message.as_bytes(), false)
		.await
		.expect("train");
	let rows = tokens_of(&pool, &taught).await;
	assert_eq!(rows.len(), MAX_TRAIN_TOKENS, "the cap held");
	assert!(
		rows == tokens_of(&pool, &trained).await,
		"the keyed sample is the one the server takes"
	);
	for scope in [&taught, &trained] {
		store.forget_scope(scope).await.expect("cleanup");
	}
}

#[tokio::test]
async fn a_message_read_in_part_is_learned_from_what_was_read() {
	let Some((_, store)) = connect().await else {
		return;
	};
	let store: BayesStore = store.with_learn_limits(LearnLimits::default());
	let account = fresh_account();
	let big = format!(
		"Subject: long\r\n\r\n{}\r\n",
		"filler ".repeat(2_000_000) + "needle token at the very end"
	);
	assert_eq!(
		store
			.learn(&account, big.as_bytes(), true)
			.await
			.expect("lesson"),
		LearnOutcome::Learned
	);
	let stats = store.learning_stats(&account).await.expect("stats");
	assert!(
		stats.token_rows <= i64::try_from(MAX_TRAIN_TOKENS).unwrap(),
		"{} rows from a message of 14 MB",
		stats.token_rows
	);
	store.forget_scope(&account).await.expect("cleanup");
}
