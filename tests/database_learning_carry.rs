//! Live-database tests for the count of token rows an account holds: where it
//! starts for an account that learned before the record existed, and that it
//! never drifts from the rows that are really there. Run only when
//! `DATABASE_URL` is set.

mod learning_support;

use epistle::antispam::learning::{LearnLimits, LearnOutcome};
use learning_support::*;
use sqlx::PgPool;

/// Rows an account holds in `bayes_token`, counted.
async fn real_rows(pool: &PgPool, scope: &str) -> i64 {
	sqlx::query_scalar("SELECT COUNT(*) FROM bayes_token WHERE scope = $1")
		.bind(scope)
		.fetch_one(pool)
		.await
		.expect("rows")
}

/// `words` words no other message shares, as a header-less body.
fn words(tag: &str, words: usize) -> String {
	(0..words).map(|n| format!("{tag}w{n}z ")).collect()
}

#[tokio::test]
async fn switching_learning_off_and_on_does_not_forget_the_rows_already_held() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 400,
		..LearnLimits::default()
	});
	let account = fresh_account();
	// Taught by the path that existed before the record: no row in bayes_learning.
	store
		.train(&account, &words("old", 300), true)
		.await
		.expect("older lessons");
	assert_eq!(real_rows(&pool, &account).await, 300);
	// The operator switches the account off and on before it learns anything.
	assert!(store.set_learning(&account, false).await.expect("off"));
	assert!(store.set_learning(&account, true).await.expect("on"));
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		300,
		"the row made by the switch knows what the account already holds"
	);
	assert_eq!(
		store
			.learn(&account, words("new", 200).as_bytes(), true)
			.await
			.expect("lesson"),
		LearnOutcome::Refused,
		"300 rows held plus 200 new ones is past 400"
	);
	assert_eq!(real_rows(&pool, &account).await, 300, "nothing was written");
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn the_status_of_an_account_that_never_learned_counts_its_rows() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store
		.train(&account, &words("old", 50), false)
		.await
		.expect("older lessons");
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		50,
		"an account with no record still shows the rows it holds"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn an_account_over_its_ceiling_still_learns_what_adds_no_row() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 400,
		..LearnLimits::default()
	});
	let account = fresh_account();
	store
		.train(&account, &words("big", 500), true)
		.await
		.expect("older lessons");
	assert_eq!(real_rows(&pool, &account).await, 500, "past the ceiling");
	// Words the account already has: no row grows.
	assert_eq!(
		store
			.learn(&account, words("big", 20).as_bytes(), true)
			.await
			.expect("known words"),
		LearnOutcome::Learned
	);
	// A word it has not: a row would grow.
	assert_eq!(
		store
			.learn(&account, b"entirely unseen vocabulary here", true)
			.await
			.expect("new words"),
		LearnOutcome::Refused
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_record_born_while_the_account_is_being_removed_counts_what_is_left() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store
		.train(&account, &words("gone", 2000), true)
		.await
		.expect("older lessons");
	store
		.learn(&account, b"alpha bravo charlie", true)
		.await
		.expect("first lesson");
	// What the removal does, held open: the record and the rows go but the
	// transaction has not committed.
	let mut removal = pool.begin().await.expect("begin");
	for statement in [
		"DELETE FROM bayes_learning WHERE scope = $1",
		"DELETE FROM bayes_learned WHERE scope = $1",
		"DELETE FROM bayes_corpus WHERE scope = $1",
		"DELETE FROM bayes_token WHERE scope = $1",
	] {
		sqlx::query(statement)
			.bind(&account)
			.execute(&mut *removal)
			.await
			.expect("delete");
	}
	let learner = store.clone();
	let name = account.clone();
	let lesson = tokio::spawn(async move {
		learner
			.learn(&name, b"delta echo foxtrot golf hotel", true)
			.await
	});
	tokio::time::sleep(std::time::Duration::from_millis(400)).await;
	removal.commit().await.expect("commit the removal");
	assert_eq!(
		lesson.await.expect("join").expect("lesson"),
		LearnOutcome::Learned
	);
	let rows = real_rows(&pool, &account).await;
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		rows,
		"the count is what is left, not what was there before the removal"
	);
	store.forget_scope(&account).await.expect("cleanup");
}
