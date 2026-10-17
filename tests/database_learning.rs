//! Live-database tests for what a user's decisions teach the corpus of
//! their account: one lesson per message, a changed mind taking the earlier
//! lesson back, the switch, the reset and the all-or-nothing write. They
//! need a real PostgreSQL and only run when `DATABASE_URL` is set; otherwise
//! they skip so the default run needs no database.

mod learning_support;

use epistle::antispam::corpus::SHARED;
use epistle::antispam::learning::LearnOutcome;
use learning_support::*;

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
