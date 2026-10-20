//! Live-database tests for the ceilings of an account's corpus: token rows,
//! tokens a day, the ledger, and the cap of one lesson. Run only when
//! `DATABASE_URL` is set.

mod learning_support;

use epistle::antispam::learning::{LearnLimits, LearnOutcome, MAX_LEARN_TOKENS};
use learning_support::*;

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
