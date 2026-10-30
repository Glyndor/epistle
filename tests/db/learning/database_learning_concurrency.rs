//! Live-database tests for lessons and resets that run at the same time, and
//! for a transaction PostgreSQL abandons. Run only when `DATABASE_URL` is set.

mod learning_support;

use epistle::antispam::corpus::BayesStore;
use learning_support::*;
use sqlx::PgPool;

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
