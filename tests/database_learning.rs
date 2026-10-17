//! Live-database tests for what a user's decisions teach the corpus of
//! their account: one lesson per message, a changed mind taking the earlier
//! lesson back, the switch, the ledger limit and the all-or-nothing write.
//! They need a real PostgreSQL and only run when `DATABASE_URL` is set;
//! otherwise they skip so the default run needs no database.

use epistle::antispam::corpus::{BayesStore, SHARED};
use epistle::antispam::learning::{LearnLimits, LearnOutcome, MAX_LEARN_TOKENS};
use epistle::config::DatabaseTls;
use sqlx::PgPool;

fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A 32-byte key minted at run time, so no literal reaches `with_key`.
fn fixture_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key
}

/// An account name no other test or earlier run uses.
fn fresh_account() -> String {
	format!("learn-{}", uuid::Uuid::now_v7().simple())
}

async fn connect() -> Option<(PgPool, BayesStore)> {
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

const SPAM: &[u8] = b"Subject: cheap pills\r\n\r\nbuy cheap pills discount viagra now\r\n";
const OTHER: &[u8] = b"Subject: agenda\r\n\r\nmeeting notes agenda project review\r\n";

/// (ham, spam) sums over every token row of the scope, and the row count.
async fn token_sums(pool: &PgPool, scope: &str) -> (i64, i64, i64) {
	sqlx::query_as(
		"SELECT COALESCE(SUM(ham_count), 0)::bigint, COALESCE(SUM(spam_count), 0)::bigint, \
		 COUNT(*) FROM bayes_token WHERE scope = $1",
	)
	.bind(scope)
	.fetch_one(pool)
	.await
	.expect("token sums")
}

async fn totals(store: &BayesStore, scope: &str) -> (u64, u64) {
	let corpus = store.corpus(scope).await.expect("corpus");
	(corpus.ham_messages, corpus.spam_messages)
}

#[tokio::test]
async fn the_same_verdict_twice_counts_once() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("first"),
		LearnOutcome::Learned
	);
	let (_, spam_tokens, rows) = token_sums(&pool, &account).await;
	assert!(rows > 0, "the first lesson wrote token rows");
	for _ in 0..3 {
		assert_eq!(
			store.learn(&account, SPAM, true).await.expect("again"),
			LearnOutcome::Repeated
		);
	}
	assert_eq!(totals(&store, &account).await, (0, 1), "one spam message");
	assert_eq!(
		token_sums(&pool, &account).await,
		(0, spam_tokens, rows),
		"the tokens were counted once"
	);
	let stats = store.learning_stats(&account).await.expect("stats");
	assert_eq!(
		(stats.spam_learned, stats.repeated, stats.entries),
		(1, 3, 1)
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_message_that_goes_back_and_forth_leaves_the_corpus_where_the_last_move_put_it() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("spam");
	let (_, tokens, rows) = token_sums(&pool, &account).await;
	for round in 0..4 {
		assert_eq!(
			store.learn(&account, SPAM, false).await.expect("ham"),
			LearnOutcome::Relearned,
			"round {round}: out of Junk"
		);
		assert_eq!(totals(&store, &account).await, (1, 0), "round {round}: ham");
		assert_eq!(token_sums(&pool, &account).await, (tokens, 0, rows));
		assert_eq!(
			store.learn(&account, SPAM, true).await.expect("spam"),
			LearnOutcome::Relearned,
			"round {round}: back into Junk"
		);
		assert_eq!(
			totals(&store, &account).await,
			(0, 1),
			"round {round}: spam"
		);
		assert_eq!(token_sums(&pool, &account).await, (0, tokens, rows));
	}
	let stats = store.learning_stats(&account).await.expect("stats");
	assert_eq!(
		stats.entries, 1,
		"one message in the ledger however often it moved"
	);
	assert_eq!(stats.unlearned, 8);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn taking_back_a_lesson_removes_the_tokens_only_that_message_brought() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store
		.learn(&account, OTHER, true)
		.await
		.expect("other as spam");
	store.learn(&account, SPAM, true).await.expect("spam");
	let before = token_sums(&pool, &account).await;
	store.learn(&account, SPAM, false).await.expect("flip");
	store.learn(&account, SPAM, true).await.expect("flip back");
	assert_eq!(
		token_sums(&pool, &account).await,
		before,
		"a round trip leaves every count as it was"
	);
	store.learn(&account, SPAM, false).await.expect("ham");
	assert_eq!(totals(&store, &account).await, (1, 1));
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn an_account_with_learning_off_teaches_nothing_until_it_is_switched_on() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	assert!(store.set_learning(&account, false).await.expect("off"));
	assert!(
		!store
			.set_learning(&account, false)
			.await
			.expect("off again")
	);
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("learn"),
		LearnOutcome::Disabled
	);
	assert_eq!(totals(&store, &account).await, (0, 0));
	assert_eq!(token_sums(&pool, &account).await, (0, 0, 0));
	assert!(!store.learning_stats(&account).await.expect("stats").enabled);
	assert!(store.set_learning(&account, true).await.expect("on"));
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("learn"),
		LearnOutcome::Learned
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// A window of `words` tokens no other lesson shares.
fn distinct_window(lesson: usize, words: usize) -> Vec<u8> {
	let mut window = String::new();
	for n in 0..words {
		window.push_str(&format!("u{lesson}x{n} "));
	}
	window.into_bytes()
}

#[tokio::test]
async fn an_account_cannot_hold_more_token_rows_than_its_ceiling() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 20_000,
		..LearnLimits::default()
	});
	let account = fresh_account();
	let mut learned = 0;
	let mut refused = 0;
	for lesson in 0..20 {
		match store
			.learn(&account, &distinct_window(lesson, 5_000), lesson % 2 == 0)
			.await
			.expect("lesson")
		{
			LearnOutcome::Learned => learned += 1,
			LearnOutcome::Refused => refused += 1,
			other => panic!("lesson {lesson}: {other:?}"),
		}
	}
	assert_eq!(
		(learned, refused),
		(4, 16),
		"four lessons fit, the rest are refused"
	);
	let (_, _, rows) = token_sums(&pool, &account).await;
	assert_eq!(rows, 20_000, "the account holds exactly its ceiling");
	let stats = store.learning_stats(&account).await.expect("stats");
	assert_eq!((stats.refused, stats.token_rows), (16, 20_000));
	assert_eq!(
		totals(&store, &account).await,
		(2, 2),
		"refused lessons taught nothing"
	);
	// A message that only touches rows the account already holds still fits.
	assert_eq!(
		store
			.learn(&account, &distinct_window(0, 5_000), false)
			.await
			.expect("flip"),
		LearnOutcome::Relearned
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn an_account_has_a_budget_of_tokens_a_day() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		tokens_per_day: 12_000,
		..LearnLimits::default()
	});
	let account = fresh_account();
	let first = distinct_window(1, 5_000);
	let second = distinct_window(2, 5_000);
	assert_eq!(
		store.learn(&account, &first, true).await.expect("1"),
		LearnOutcome::Learned
	);
	assert_eq!(
		store.learn(&account, &first, false).await.expect("flip"),
		LearnOutcome::Relearned,
		"taking a lesson back writes the same rows, so it spends the same tokens"
	);
	assert_eq!(
		store.learn(&account, &second, true).await.expect("2"),
		LearnOutcome::Throttled,
		"5000 + 5000 + 5000 does not fit in 12000"
	);
	assert_eq!(
		store.learn(&account, &first, false).await.expect("repeat"),
		LearnOutcome::Repeated,
		"a repeated verdict writes nothing and costs nothing"
	);
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.throttled,
		1
	);
	assert_eq!(
		totals(&store, &account).await,
		(1, 0),
		"the throttled lesson taught nothing"
	);
	sqlx::query("UPDATE bayes_learning SET budget_day = CURRENT_DATE - 1 WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("yesterday");
	assert_eq!(
		store
			.learn(&account, &second, true)
			.await
			.expect("next day"),
		LearnOutcome::Learned,
		"a new day starts a new budget"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn lessons_that_reuse_words_only_pay_for_the_rows_they_add() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 6_000,
		..LearnLimits::default()
	});
	let account = fresh_account();
	let first = distinct_window(1, 5_000);
	// The first 4900 words again and 100 new ones: 100 new rows.
	let mut second = distinct_window(1, 4_900);
	second.extend(distinct_window(2, 100));
	assert_eq!(
		store.learn(&account, &first, true).await.expect("1"),
		LearnOutcome::Learned
	);
	assert_eq!(
		store.learn(&account, &second, true).await.expect("2"),
		LearnOutcome::Learned,
		"5100 rows fit in 6000 because 4900 of the words were already there"
	);
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		5_100
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn rows_taught_before_the_ledger_existed_count_against_the_ceiling() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 8,
		..LearnLimits::default()
	});
	let account = fresh_account();
	// The path that taught accounts before the ledger: no row in bayes_learning.
	store
		.train(&account, "alpha bravo charlie delta echo foxtrot", true)
		.await
		.expect("older lesson");
	assert_eq!(
		store
			.learn(&account, b"golf hotel india juliet kilo", true)
			.await
			.expect("learn"),
		LearnOutcome::Refused,
		"six rows already held plus five new ones is past eight"
	);
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		6
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_full_ledger_forgets_its_oldest_messages_instead_of_refusing() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		ledger_entries: 5,
		..LearnLimits::default()
	});
	let account = fresh_account();
	let messages: Vec<Vec<u8>> = (0..7).map(|n| distinct_window(n, 20)).collect();
	for (n, message) in messages.iter().enumerate() {
		assert_eq!(
			store.learn(&account, message, false).await.expect("lesson"),
			LearnOutcome::Learned,
			"message {n}"
		);
	}
	assert_eq!(
		store.learning_stats(&account).await.expect("stats").entries,
		5
	);
	assert_eq!(
		store
			.learn(&account, &messages[6], false)
			.await
			.expect("newest"),
		LearnOutcome::Repeated,
		"the newest message is still recorded"
	);
	assert_eq!(
		store
			.learn(&account, &messages[0], false)
			.await
			.expect("oldest"),
		LearnOutcome::Learned,
		"the oldest message was forgotten, so it is new again"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// The record and the corpus can disagree (rows deleted by hand, a restore
/// of one table). Taking a lesson back then must clamp at zero, not write a
/// negative count that would flip the sign of a probability.
#[tokio::test]
async fn taking_a_lesson_back_never_writes_a_negative_count() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("spam");
	// Rows gone: the flip has nothing to subtract from.
	sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("tokens");
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("totals");
	assert_eq!(
		store.learn(&account, SPAM, false).await.expect("flip"),
		LearnOutcome::Relearned
	);
	let negatives: i64 = sqlx::query_scalar(
		"SELECT (SELECT COUNT(*) FROM bayes_token WHERE scope = $1 AND (ham_count < 0 OR spam_count < 0)) \
		 + (SELECT COUNT(*) FROM bayes_corpus WHERE scope = $1 AND (ham_messages < 0 OR spam_messages < 0))",
	)
	.bind(&account)
	.fetch_one(&pool)
	.await
	.expect("negatives");
	assert_eq!(
		negatives, 0,
		"no count went below zero after the rows were deleted"
	);
	// Rows present but already at zero: the update clamps.
	sqlx::query("UPDATE bayes_token SET ham_count = 0 WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("zero tokens");
	sqlx::query("UPDATE bayes_corpus SET ham_messages = 0 WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("zero totals");
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("flip back"),
		LearnOutcome::Relearned
	);
	let negatives: i64 = sqlx::query_scalar(
		"SELECT (SELECT COUNT(*) FROM bayes_token WHERE scope = $1 AND (ham_count < 0 OR spam_count < 0)) \
		 + (SELECT COUNT(*) FROM bayes_corpus WHERE scope = $1 AND (ham_messages < 0 OR spam_messages < 0))",
	)
	.bind(&account)
	.fetch_one(&pool)
	.await
	.expect("negatives");
	assert_eq!(
		negatives, 0,
		"no count went below zero on the existing rows either"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn the_shared_corpus_never_learns_from_a_user() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let before = token_sums(&pool, SHARED).await;
	let totals_before = totals(&store, SHARED).await;
	assert_eq!(
		store.learn(SHARED, SPAM, true).await.expect("learn"),
		LearnOutcome::Skipped
	);
	assert_eq!(token_sums(&pool, SHARED).await.2, before.2);
	assert_eq!(totals(&store, SHARED).await, totals_before);
	assert!(!store.set_learning(SHARED, false).await.expect("no switch"));
}

#[tokio::test]
async fn one_account_never_teaches_another() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let (alice, bob) = (fresh_account(), fresh_account());
	store.learn(&alice, SPAM, true).await.expect("alice");
	assert_eq!(totals(&store, &bob).await, (0, 0));
	assert_eq!(token_sums(&pool, &bob).await, (0, 0, 0));
	assert_eq!(
		store.learn(&bob, SPAM, false).await.expect("bob"),
		LearnOutcome::Learned,
		"bob has his own ledger: the same message is new to him"
	);
	assert_eq!(totals(&store, &alice).await, (0, 1));
	assert_eq!(totals(&store, &bob).await, (1, 0));
	store.forget_scope(&alice).await.expect("cleanup alice");
	store.forget_scope(&bob).await.expect("cleanup bob");
}

#[tokio::test]
async fn a_ledger_that_cannot_be_written_leaves_the_corpus_untouched() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	// Only accounts named like this one are refused, so a test running next
	// to this one is not touched.
	let account = format!("ledger-refused-{}", uuid::Uuid::now_v7().simple());
	sqlx::query(
		"CREATE OR REPLACE FUNCTION refuse_ledger_test() RETURNS trigger AS $$ BEGIN \
		 RAISE EXCEPTION 'ledger refused'; END $$ LANGUAGE plpgsql",
	)
	.execute(&pool)
	.await
	.expect("function");
	sqlx::query(
		"CREATE OR REPLACE TRIGGER refuse_ledger_test BEFORE INSERT ON bayes_learned \
		 FOR EACH ROW WHEN (NEW.scope LIKE 'ledger-refused-%') \
		 EXECUTE FUNCTION refuse_ledger_test()",
	)
	.execute(&pool)
	.await
	.expect("trigger");
	let result = store.learn(&account, SPAM, true).await;
	sqlx::query("DROP TRIGGER IF EXISTS refuse_ledger_test ON bayes_learned")
		.execute(&pool)
		.await
		.expect("drop trigger");
	assert!(result.is_err(), "an unrecordable lesson is an error");
	assert_eq!(
		totals(&store, &account).await,
		(0, 0),
		"no message total moved"
	);
	assert_eq!(
		token_sums(&pool, &account).await,
		(0, 0, 0),
		"no token moved"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_window_made_of_distinct_words_touches_a_bounded_number_of_rows() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	let mut window = String::new();
	for n in 0..60_000 {
		window.push_str(&format!("w{n} "));
	}
	assert_eq!(
		store
			.learn(&account, window.as_bytes(), true)
			.await
			.expect("learn"),
		LearnOutcome::Learned
	);
	let (_, _, rows) = token_sums(&pool, &account).await;
	assert_eq!(
		rows,
		i64::try_from(MAX_LEARN_TOKENS).expect("cap fits"),
		"one lesson never writes more than the token cap"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn hostile_bytes_are_learned_as_text_and_do_nothing_else() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	let mut window = b"\x00\x1b[2J\xff\xfe'; DROP TABLE bayes_token; -- \r\n".to_vec();
	window.extend_from_slice(b"win free money now\x00\x00");
	assert_eq!(
		store.learn(&account, &window, true).await.expect("learn"),
		LearnOutcome::Learned
	);
	let (_, spam, rows) = token_sums(&pool, &account).await;
	assert!(rows > 0 && spam > 0, "the readable words were counted");
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn removing_an_account_drops_what_it_learned_and_its_switch() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("learn");
	store.set_learning(&account, false).await.expect("off");
	store.forget_scope(&account).await.expect("forget");
	let ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bayes_learned WHERE scope = $1")
		.bind(&account)
		.fetch_one(&pool)
		.await
		.expect("ledger");
	assert_eq!(ledger, 0, "the ledger is gone");
	let stats = store.learning_stats(&account).await.expect("stats");
	assert!(stats.enabled, "a recreated account starts with learning on");
	assert_eq!(stats.entries, 0);
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("learn"),
		LearnOutcome::Learned,
		"the same message is new again"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// Wait until `check` holds, up to five seconds.
async fn eventually<F, Fut>(mut check: F) -> bool
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	for _ in 0..100 {
		if check().await {
			return true;
		}
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	false
}

#[tokio::test]
async fn lessons_that_go_through_the_queue_count_once_per_message() {
	use epistle::antispam::training_queue::{TrainingJob, TrainingQueue};
	use std::sync::Arc;

	let Some((_pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	let dir = tempfile::tempdir().expect("tempdir");
	let in_junk = dir.path().join("in-junk.eml");
	let back_in_inbox = dir.path().join("back-in-inbox.eml");
	std::fs::write(&in_junk, SPAM).expect("write");
	// The same bytes under another name: what a move leaves behind.
	std::fs::write(&back_in_inbox, SPAM).expect("write");
	let queue = TrainingQueue::start(
		Arc::new(store.clone()),
		epistle::storage::MessageCrypto::disabled(),
		Arc::new(epistle::metrics::Metrics::new()),
	);
	let job = |path: &std::path::Path, spam: bool| TrainingJob {
		account: account.clone(),
		path: path.to_path_buf(),
		spam,
	};
	assert!(queue.submit(job(&in_junk, true)));
	assert!(queue.submit(job(&in_junk, true)), "the same lesson twice");
	assert!(
		queue.submit(job(&back_in_inbox, false)),
		"and then the other way"
	);
	let settled = eventually(|| async {
		let stats = store.learning_stats(&account).await.expect("stats");
		stats.spam_learned == 1 && stats.ham_learned == 1 && stats.repeated == 1
	})
	.await;
	assert!(
		settled,
		"the worker taught, ignored the repeat and took the lesson back"
	);
	assert_eq!(
		totals(&store, &account).await,
		(1, 0),
		"the last verdict stands"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_message_of_a_million_distinct_words_is_trimmed_before_it_is_counted() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	let mut window = String::with_capacity(8 << 20);
	for n in 0..1_000_000 {
		window.push_str(&format!("w{n} "));
	}
	assert_eq!(
		store
			.learn(&account, window.as_bytes(), false)
			.await
			.expect("ham"),
		LearnOutcome::Learned
	);
	let after_ham = token_sums(&pool, &account).await;
	assert!(
		after_ham.2 <= i64::try_from(MAX_LEARN_TOKENS).expect("cap fits"),
		"a million words wrote {} rows",
		after_ham.2
	);
	// Into Junk and out again, as a move there and back would.
	store
		.learn(&account, window.as_bytes(), true)
		.await
		.expect("spam");
	store
		.learn(&account, window.as_bytes(), false)
		.await
		.expect("ham again");
	assert_eq!(
		token_sums(&pool, &account).await,
		after_ham,
		"the round trip leaves every counter as it was"
	);
	assert_eq!(totals(&store, &account).await, (1, 0));
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn taking_a_lesson_back_moves_only_the_tokens_that_were_counted() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("spam");
	let (_, spam_before, rows) = token_sums(&pool, &account).await;
	assert!(spam_before > 3, "the message has more than three tokens");
	// As if an older release had counted only the first three.
	sqlx::query("UPDATE bayes_learned SET tokens = 3 WHERE scope = $1")
		.bind(&account)
		.execute(&pool)
		.await
		.expect("shrink the record");
	store.learn(&account, SPAM, false).await.expect("ham");
	let (ham, spam, _) = token_sums(&pool, &account).await;
	assert_eq!(ham, 3, "only the counted tokens moved to ham");
	assert_eq!(spam, spam_before - 3, "only the counted tokens left spam");
	assert!(rows > 3);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_reset_clears_what_was_learned_and_keeps_the_switch() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("spam");
	store.set_learning(&account, false).await.expect("off");
	let tokens = store.reset_learning(&account).await.expect("reset");
	assert!(tokens > 0, "the reset reports the token rows it dropped");
	let stats = store.learning_stats(&account).await.expect("stats");
	assert!(!stats.enabled, "a reset never turns learning back on");
	assert_eq!(
		(stats.spam_learned, stats.entries, stats.corpus_spam),
		(0, 0, 0),
		"counters, record and corpus are cleared"
	);
	assert_eq!(token_sums(&pool, &account).await, (0, 0, 0));
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("learn"),
		LearnOutcome::Disabled,
		"the account still teaches nothing"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// The server and the CLI are two processes with two `scope_lock`s, so the
/// order in which a lesson and a reset take their row locks is the only thing
/// that keeps them apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lesson_and_a_reset_from_two_processes_never_deadlock() {
	let Some((pool, server)) = connect().await else {
		return;
	};
	let cli = BayesStore::with_key(pool.clone(), fixture_key());
	let account = fresh_account();
	let learner = {
		let account = account.clone();
		tokio::spawn(async move {
			let mut errors = Vec::new();
			for i in 0..200usize {
				let mut window = format!("Subject: x{i}\r\n\r\n");
				for w in 0..800 {
					window.push_str(&format!("tok{w:05}q{} ", w % 7));
				}
				if let Err(error) = server.learn(&account, window.as_bytes(), i % 2 == 0).await {
					errors.push(error.to_string());
				}
			}
			errors
		})
	};
	let resetter = {
		let account = account.clone();
		tokio::spawn(async move {
			let mut errors = Vec::new();
			for _ in 0..40 {
				if let Err(error) = cli.reset_learning(&account).await {
					errors.push(error.to_string());
				}
				tokio::time::sleep(std::time::Duration::from_millis(5)).await;
			}
			errors
		})
	};
	let lesson_errors = learner.await.expect("learner");
	let reset_errors = resetter.await.expect("resetter");
	assert!(
		reset_errors.is_empty(),
		"{} resets failed, first: {:?}",
		reset_errors.len(),
		reset_errors.first()
	);
	assert!(
		lesson_errors.is_empty(),
		"{} lessons failed, first: {:?}",
		lesson_errors.len(),
		lesson_errors.first()
	);
	let cleaner = BayesStore::with_key(pool, fixture_key());
	cleaner.forget_scope(&account).await.expect("cleanup");
}

/// Two transactions that lock the same two rows in opposite order are set
/// against each other by PostgreSQL. The one it abandons is run again and
/// both finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_the_server_abandons_for_a_deadlock_is_run_again() {
	use epistle::antispam::learning::retry::retrying;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

	let Some((pool, _store)) = connect().await else {
		return;
	};
	let (first, second) = (fresh_account(), fresh_account());
	for scope in [&first, &second] {
		sqlx::query("INSERT INTO bayes_learning (scope) VALUES ($1)")
			.bind(scope)
			.execute(&pool)
			.await
			.expect("row");
	}
	let barrier = Arc::new(tokio::sync::Barrier::new(2));
	let attempts = Arc::new(AtomicU32::new(0));
	let crossing = |pool: PgPool, mine: String, theirs: String| {
		let (barrier, attempts) = (Arc::clone(&barrier), Arc::clone(&attempts));
		tokio::spawn(async move {
			let waited = AtomicBool::new(false);
			retrying(|| async {
				attempts.fetch_add(1, Ordering::SeqCst);
				let mut tx = pool.begin().await?;
				sqlx::query("SELECT scope FROM bayes_learning WHERE scope = $1 FOR UPDATE")
					.bind(&mine)
					.execute(&mut *tx)
					.await?;
				if !waited.swap(true, Ordering::SeqCst) {
					barrier.wait().await;
				}
				sqlx::query("SELECT scope FROM bayes_learning WHERE scope = $1 FOR UPDATE")
					.bind(&theirs)
					.execute(&mut *tx)
					.await?;
				tx.commit().await
			})
			.await
		})
	};
	let one = crossing(pool.clone(), first.clone(), second.clone());
	let two = crossing(pool.clone(), second.clone(), first.clone());
	one.await.expect("task").expect("first finishes");
	two.await.expect("task").expect("second finishes");
	assert_eq!(
		attempts.load(Ordering::SeqCst),
		3,
		"one of the two was abandoned and run again"
	);
	for scope in [&first, &second] {
		sqlx::query("DELETE FROM bayes_learning WHERE scope = $1")
			.bind(scope)
			.execute(&pool)
			.await
			.expect("cleanup");
	}
}
