//! Live-database tests that each defence of the learning module is wired to
//! the paths that need it: the retry of an abandoned transaction on every
//! write, the counters a reset leaves, the removal of an account in flight,
//! and the number `learning status` gives for what the record does not hold.
//! Run only when `DATABASE_URL` is set.

mod learning_support;

use epistle::antispam::learning::{LearnLimits, LearnOutcome};
use learning_support::*;
use sqlx::PgPool;

/// A trap on `bayes_learned` for the rows of one account: the first
/// `abandon` statements it sees fail the way PostgreSQL fails a transaction it
/// abandons for a deadlock (SQLSTATE 40P01). The account's name keeps it from
/// touching the other tests, which share the database.
struct Trap {
	pool: PgPool,
	name: String,
}

impl Trap {
	async fn set(pool: &PgPool, account: &str, event: &str, abandon: i64) -> Trap {
		let name = format!("trap_{}", uuid::Uuid::now_v7().simple());
		// The identifiers are made here from a UUID, the account name is
		// compared in the function body as a bound literal inside quotes
		// that a generated name cannot break.
		assert!(
			account
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-')
		);
		for statement in [
			format!("CREATE SEQUENCE {name}"),
			format!(
				"CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN \
				 IF COALESCE(NEW.scope, OLD.scope) = '{account}' AND nextval('{name}') <= {abandon} THEN \
				 RAISE EXCEPTION 'abandoned' USING ERRCODE = '40P01'; END IF; \
				 RETURN COALESCE(NEW, OLD); END $f$"
			),
			format!(
				"CREATE TRIGGER {name} BEFORE {event} ON bayes_learned \
				 FOR EACH ROW EXECUTE FUNCTION {name}()"
			),
		] {
			sqlx::query(sqlx::AssertSqlSafe(statement))
				.execute(pool)
				.await
				.expect("trap");
		}
		Trap {
			pool: pool.clone(),
			name,
		}
	}

	/// How many times the trap was reached.
	async fn reached(&self) -> i64 {
		sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
			"SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM {}",
			self.name
		)))
		.fetch_one(&self.pool)
		.await
		.expect("reached")
	}

	async fn remove(self) {
		for statement in [
			format!("DROP TRIGGER {} ON bayes_learned", self.name),
			format!("DROP FUNCTION {}()", self.name),
			format!("DROP SEQUENCE {}", self.name),
		] {
			sqlx::query(sqlx::AssertSqlSafe(statement))
				.execute(&self.pool)
				.await
				.expect("untrap");
		}
	}
}

#[tokio::test]
async fn a_lesson_abandoned_by_the_database_is_run_again() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	let trap = Trap::set(&pool, &account, "INSERT", 1).await;
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("lesson"),
		LearnOutcome::Learned,
		"the first attempt was abandoned and the second taught"
	);
	assert_eq!(trap.reached().await, 2, "the lesson was attempted twice");
	assert_eq!(totals(&store, &account).await, (0, 1));
	trap.remove().await;
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn a_reset_abandoned_by_the_database_is_run_again() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("lesson");
	let trap = Trap::set(&pool, &account, "DELETE", 1).await;
	store.reset_learning(&account).await.expect("reset");
	assert_eq!(trap.reached().await, 2, "the reset was attempted twice");
	assert_eq!(
		totals(&store, &account).await,
		(0, 0),
		"and it dropped the corpus"
	);
	trap.remove().await;
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn the_removal_of_an_account_abandoned_by_the_database_is_run_again() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store.learn(&account, SPAM, true).await.expect("lesson");
	let trap = Trap::set(&pool, &account, "DELETE", 1).await;
	store.forget_scope(&account).await.expect("removal");
	assert_eq!(trap.reached().await, 2, "the removal was attempted twice");
	assert_eq!(totals(&store, &account).await, (0, 0));
	trap.remove().await;
}

#[tokio::test]
async fn after_a_reset_the_account_has_its_whole_ceiling_again() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let store = store.with_learn_limits(LearnLimits {
		token_rows: 12,
		..LearnLimits::default()
	});
	let account = fresh_account();
	let ten: Vec<String> = (0..10).map(|n| format!("wordx{n}")).collect();
	let again: Vec<String> = (0..10).map(|n| format!("wordy{n}")).collect();
	assert_eq!(
		store
			.learn(&account, ten.join(" ").as_bytes(), true)
			.await
			.expect("first"),
		LearnOutcome::Learned
	);
	store.reset_learning(&account).await.expect("reset");
	assert_eq!(
		store
			.learning_stats(&account)
			.await
			.expect("stats")
			.token_rows,
		0,
		"the reset left no rows counted"
	);
	assert_eq!(
		store
			.learn(&account, again.join(" ").as_bytes(), true)
			.await
			.expect("second"),
		LearnOutcome::Learned,
		"ten rows fit again after the reset"
	);
	store.forget_scope(&account).await.expect("cleanup");
}

#[tokio::test]
async fn an_account_being_removed_learns_nothing() {
	let Some((pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	store
		.tombstones()
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.insert(account.clone());
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("lesson"),
		LearnOutcome::Skipped
	);
	let rows: i64 = sqlx::query_scalar(
		"SELECT (SELECT COUNT(*) FROM bayes_learning WHERE scope = $1) \
		 + (SELECT COUNT(*) FROM bayes_token WHERE scope = $1)",
	)
	.bind(&account)
	.fetch_one(&pool)
	.await
	.expect("rows");
	assert_eq!(rows, 0, "no record and no token was written");
	store
		.tombstones()
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.remove(&account);
}

#[tokio::test]
async fn what_the_record_does_not_hold_is_reported_as_unrecorded() {
	let Some((_pool, store)) = connect().await else {
		return;
	};
	let account = fresh_account();
	// Taught before the record existed: two spam and one ham, no ledger.
	store
		.train(&account, "alpha bravo", true)
		.await
		.expect("one");
	store
		.train(&account, "charlie delta", true)
		.await
		.expect("two");
	store
		.train(&account, "echo foxtrot", false)
		.await
		.expect("three");
	assert_eq!(
		store.learn(&account, SPAM, true).await.expect("lesson"),
		LearnOutcome::Learned
	);
	let stats = store.learning_stats(&account).await.expect("stats");
	assert_eq!(
		(
			stats.corpus_spam + stats.corpus_ham,
			stats.entries,
			stats.unrecorded
		),
		(4, 1, 3),
		"four messages in the corpus, one in the record"
	);
	store.forget_scope(&account).await.expect("cleanup");
}
