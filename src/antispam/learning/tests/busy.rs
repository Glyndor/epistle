//! The time charged to an account is its own: the wait behind somebody else's
//! lock is not part of it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::limiter::LearnLimiter;
use super::{LearnOutcome, Lesson};
use crate::antispam::trainer::{BayesTrainer, TrainerFuture};
use crate::antispam::training_queue::{TrainingJob, TrainingQueue};
use crate::metrics::Metrics;

/// A trainer that takes `wait` of wall time and says its own work was `busy`,
/// like a lesson that queued behind another one for the store's lock.
struct WaitsBehindOthers {
	wait: Duration,
	busy: Duration,
}

impl BayesTrainer for WaitsBehindOthers {
	fn train<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async {})
	}
	fn learn<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, Lesson> {
		let (wait, busy) = (self.wait, self.busy);
		Box::pin(async move {
			tokio::time::sleep(wait).await;
			Lesson {
				outcome: LearnOutcome::Learned,
				busy,
			}
		})
	}
	fn score_for_account<'a>(
		&'a self,
		_a: &'a str,
		_t: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>> {
		Box::pin(async { None })
	}
}

#[tokio::test]
async fn an_account_is_not_charged_for_the_time_it_waited_behind_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	let message = dir.path().join("m.eml");
	std::fs::write(&message, b"Subject: hi\r\n\r\nbody\r\n").expect("write");
	let metrics = Arc::new(Metrics::new());
	let queue = TrainingQueue::start_with(
		Arc::new(WaitsBehindOthers {
			wait: Duration::from_millis(400),
			busy: Duration::from_millis(5),
		}),
		crate::storage::MessageCrypto::disabled(),
		Arc::clone(&metrics),
		LearnLimiter::new(100, 1000, 16).with_max_busy(Duration::from_millis(200)),
	);
	let job = TrainingJob {
		account: "victim".to_string(),
		path: message,
		spam: true,
	};
	assert!(queue.submit(job.clone()), "the first lesson is accepted");
	let started = Instant::now();
	while queue.pending_for("victim") > 0 {
		assert!(
			started.elapsed() < Duration::from_secs(5),
			"the worker never finished"
		);
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert!(
		started.elapsed() >= Duration::from_millis(350),
		"the lesson really waited"
	);
	assert!(
		queue.submit(job),
		"a lesson that waited 400 ms but worked 5 ms leaves the account its time"
	);
}

/// A store on the database of the run, or `None` when there is none.
async fn live_store() -> Option<crate::antispam::corpus::BayesStore> {
	let url = std::env::var("DATABASE_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	Some(crate::antispam::corpus::BayesStore::with_key(
		pool, [9u8; 32],
	))
}

/// Somebody else holds the store's lock (the training of the shared corpus
/// does) for a second and a half: the lesson that queues behind it waited, and
/// worked for milliseconds.
#[tokio::test]
async fn the_wait_behind_the_stores_lock_is_not_the_lessons_busy_time() {
	let Some(store) = live_store().await else {
		return;
	};
	let account = format!("busy-{}", uuid::Uuid::now_v7().simple());
	let holder = store.clone();
	let release = tokio::spawn(async move {
		let _held = holder.scope_lock.lock().await;
		tokio::time::sleep(Duration::from_millis(1500)).await;
	});
	tokio::time::sleep(Duration::from_millis(100)).await;
	let started = Instant::now();
	let lesson = store
		.learn_timed(&account, b"Subject: hi\r\n\r\nbuy cheap pills\r\n", true)
		.await
		.expect("lesson");
	let waited = started.elapsed();
	release.await.expect("holder");
	assert_eq!(lesson.outcome, LearnOutcome::Learned);
	assert!(
		waited >= Duration::from_millis(1300),
		"the lesson queued behind the lock ({waited:?})"
	);
	assert!(
		lesson.busy < Duration::from_millis(500),
		"{:?} of {waited:?} was charged to the account",
		lesson.busy
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// The same for a pool whose only connection is in use: the wait for it is
/// not the lesson's work either.
#[tokio::test]
async fn the_wait_for_a_pooled_connection_is_not_the_lessons_busy_time() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		return;
	};
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 1, None)
		.await
		.expect("connect and migrate");
	let store = crate::antispam::corpus::BayesStore::with_key(pool.clone(), [9u8; 32]);
	let account = format!("busy-{}", uuid::Uuid::now_v7().simple());
	let held = pool.acquire().await.expect("the only connection");
	let release = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(1500)).await;
		drop(held);
	});
	let started = Instant::now();
	let lesson = store
		.learn_timed(&account, b"Subject: hi\r\n\r\nbuy cheap pills\r\n", true)
		.await
		.expect("lesson");
	let waited = started.elapsed();
	release.await.expect("holder");
	assert_eq!(lesson.outcome, LearnOutcome::Learned);
	assert!(
		waited >= Duration::from_millis(1300),
		"the lesson waited for the connection ({waited:?})"
	);
	assert!(
		lesson.busy < Duration::from_millis(500),
		"{:?} of {waited:?} was charged to the account",
		lesson.busy
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// What an account owes for a lesson is a floor as well as a ceiling: the
/// time the real store spent on it is charged whatever became of the lesson.
mod charged_at_least {
	use super::*;
	use crate::antispam::trainer::BayesTrainer;

	const TEXT: &[u8] = b"Subject: hi\r\n\r\nbuy cheap pills now\r\n";

	/// A trigger on `bayes_learned` that, for the rows of one account, sleeps
	/// `pause` seconds and then raises `code` when it is given.
	async fn slow_trap(
		pool: &sqlx::PgPool,
		account: &str,
		pause: f64,
		code: Option<&str>,
	) -> String {
		let name = format!("slow_{}", uuid::Uuid::now_v7().simple());
		assert!(
			account
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-')
		);
		let raise = code.map_or(String::new(), |code| {
			format!("RAISE EXCEPTION 'slow and abandoned' USING ERRCODE = '{code}';")
		});
		for statement in [
			format!(
				"CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN \
				 IF NEW.scope = '{account}' THEN PERFORM pg_sleep({pause}); {raise} END IF; \
				 RETURN NEW; END $f$"
			),
			format!(
				"CREATE TRIGGER {name} BEFORE INSERT ON bayes_learned \
				 FOR EACH ROW EXECUTE FUNCTION {name}()"
			),
		] {
			sqlx::query(sqlx::AssertSqlSafe(statement))
				.execute(pool)
				.await
				.expect("trap");
		}
		name
	}

	async fn drop_trap(pool: &sqlx::PgPool, name: &str) {
		for statement in [
			format!("DROP TRIGGER {name} ON bayes_learned"),
			format!("DROP FUNCTION {name}()"),
		] {
			sqlx::query(sqlx::AssertSqlSafe(statement))
				.execute(pool)
				.await
				.expect("untrap");
		}
	}

	/// Each of these tests puts a trigger on `bayes_learned` and takes it off
	/// again. Run in parallel against one database, two of them can ask for
	/// the exclusive lock on the table while the other holds a row lock, and
	/// PostgreSQL ends one with "deadlock detected". One at a time they cannot.
	static ONE_TRAP_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

	async fn lesson_behind(code: Option<&str>, pause: f64) -> Option<(Lesson, Duration)> {
		let url = std::env::var("DATABASE_URL")
			.ok()
			.filter(|u| !u.is_empty())?;
		let _alone = ONE_TRAP_AT_A_TIME.lock().await;
		let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 5, None)
			.await
			.expect("connect and migrate");
		let store = crate::antispam::corpus::BayesStore::with_key(pool.clone(), [9u8; 32]);
		let account = format!("busy-{}", uuid::Uuid::now_v7().simple());
		let trap = slow_trap(&pool, &account, pause, code).await;
		let started = Instant::now();
		let lesson = BayesTrainer::learn(&store, &account, TEXT.to_vec(), true).await;
		let wall = started.elapsed();
		drop_trap(&pool, &trap).await;
		store.forget_scope(&account).await.expect("cleanup");
		Some((lesson, wall))
	}

	#[tokio::test]
	async fn a_lesson_that_taught_is_charged_the_time_it_took() {
		let Some((lesson, _)) = lesson_behind(None, 0.5).await else {
			return;
		};
		assert_eq!(lesson.outcome, LearnOutcome::Learned);
		assert!(
			lesson.busy >= Duration::from_millis(450),
			"{:?} charged for a transaction that took half a second",
			lesson.busy
		);
	}

	#[tokio::test]
	async fn a_lesson_the_database_refused_is_charged_the_time_it_took() {
		let Some((lesson, wall)) = lesson_behind(Some("XX000"), 0.7).await else {
			return;
		};
		assert_eq!(lesson.outcome, LearnOutcome::Failed);
		assert!(
			lesson.busy >= Duration::from_millis(650),
			"{:?} charged of {wall:?} for a lesson that failed after 0.7 s",
			lesson.busy
		);
	}

	#[tokio::test]
	async fn a_lesson_abandoned_on_every_attempt_is_charged_all_of_them() {
		let Some((lesson, wall)) = lesson_behind(Some("40P01"), 0.3).await else {
			return;
		};
		assert_eq!(lesson.outcome, LearnOutcome::Failed);
		assert!(
			wall >= Duration::from_millis(1200),
			"four attempts ran ({wall:?})"
		);
		assert!(
			lesson.busy >= Duration::from_millis(1150),
			"{:?} charged of {wall:?} for four attempts of 0.3 s",
			lesson.busy
		);
	}

	#[tokio::test]
	async fn an_unreadable_message_is_charged_the_time_it_took_to_try() {
		let pool = sqlx::postgres::PgPoolOptions::new()
			.connect_lazy("postgres://nobody@127.0.0.1:1/none")
			.expect("lazy pool");
		let store = crate::antispam::corpus::BayesStore::with_key(pool, [9u8; 32]);
		crate::antispam::scoring_text::fail_next_reduction();
		let lesson = BayesTrainer::learn(&store, "alice", TEXT.to_vec(), true).await;
		assert_eq!(lesson.outcome, LearnOutcome::Unread);
		assert!(
			lesson.busy > Duration::ZERO,
			"reading the message took time and the account pays for it"
		);
	}

	/// A fifo is a message file that is slow to read: the writer comes after
	/// half a second.
	#[cfg(unix)]
	#[tokio::test]
	async fn the_time_the_worker_spends_reading_the_file_is_charged() {
		use std::io::Write;
		let dir = tempfile::tempdir().expect("tempdir");
		let path = dir.path().join("m.eml");
		let made = std::process::Command::new("mkfifo")
			.arg(&path)
			.status()
			.expect("mkfifo");
		assert!(made.success());
		let writer = {
			let path = path.clone();
			std::thread::spawn(move || {
				std::thread::sleep(Duration::from_millis(500));
				std::fs::OpenOptions::new()
					.write(true)
					.open(path)
					.expect("open fifo")
					.write_all(TEXT)
					.expect("write");
			})
		};
		let queue = TrainingQueue::start_with(
			Arc::new(crate::antispam::trainer::RecordingTrainer::new()),
			crate::storage::MessageCrypto::disabled(),
			Arc::new(Metrics::new()),
			LearnLimiter::new(100, 1000, 16).with_max_busy(Duration::from_millis(300)),
		);
		let job = TrainingJob {
			account: "reader".to_string(),
			path,
			spam: true,
		};
		assert!(queue.submit(job.clone()));
		let started = Instant::now();
		while queue.pending_for("reader") > 0 {
			assert!(started.elapsed() < Duration::from_secs(5), "never finished");
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
		writer.join().expect("writer");
		assert!(
			!queue.submit(job),
			"half a second spent reading the file is over a 300 ms budget"
		);
	}
}
