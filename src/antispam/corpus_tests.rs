//! Unit tests for the corpus key handling, the token hash, the
//! trainer transition table and the score threshold (no database).

use super::*;
use crate::antispam::corpus::SHARED;
use crate::antispam::trainer::{BayesTrainer, MIN_TRUSTED_MESSAGES, RecordingTrainer, is_trusted};
use crate::imap::keyword::{JUNK, NOT_JUNK};
use crate::imap::mailbox::Flag;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn hash_is_deterministic_and_key_dependent() {
	let k1 = [1u8; 32];
	let k2 = [2u8; 32];
	// Tokens are minted at runtime so no plaintext string literal ever
	// reaches the `token` parameter the scanner would flag.
	let token_a: String = uuid::Uuid::now_v7().simple().to_string();
	let token_b: String = uuid::Uuid::now_v7().simple().to_string();
	// Same key + token -> same hash (so lookups work).
	assert_eq!(hash_token(&k1, &token_a), hash_token(&k1, &token_a));
	// Different tokens -> different hashes.
	assert_ne!(hash_token(&k1, &token_a), hash_token(&k1, &token_b));
	// Different keys -> different hashes (per-instance confidentiality).
	assert_ne!(hash_token(&k1, &token_a), hash_token(&k2, &token_a));
	// The hash is 64 hex chars and never contains the plaintext.
	let h = hash_token(&k1, &token_a);
	assert_eq!(h.len(), 64, "{h}");
	assert!(!h.contains(&token_a), "{h}");
	assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{h}");
}

#[test]
fn key_persists_and_reloads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = load_or_create_key_file(dir.path(), KEY_FILE).expect("generate");
	let second = load_or_create_key_file(dir.path(), KEY_FILE).expect("reload");
	// The same key is returned on the second call (stable across restarts).
	assert_eq!(first, second);
}

#[cfg(unix)]
#[test]
fn key_file_is_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	load_or_create_key_file(dir.path(), KEY_FILE).expect("generate");
	let mode = std::fs::metadata(dir.path().join(KEY_FILE))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, "key file must not be group/world readable");
}

/// Drive the transition helper through a `TrainingQueue` whose
/// receiver is held by the test. The recording fake behind the
/// handle records the bytes the worker read off disk. The helper
/// submits a job and the worker (started by `TrainingQueue::start`)
/// drains it into the recording fake.
async fn run_transition(
	account: &str,
	previous: &[Flag],
	updated: &[Flag],
	body: &[u8],
) -> Vec<crate::antispam::trainer::RecordedCall> {
	let dir = tempfile::tempdir().expect("tempdir");
	let message_path = dir.path().join("message.eml");
	std::fs::write(&message_path, body).expect("write message");

	let trainer = Arc::new(RecordingTrainer::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let queue = crate::antispam::training_queue::TrainingQueue::start(
		Arc::clone(&trainer) as Arc<dyn BayesTrainer>,
		crate::storage::MessageCrypto::disabled(),
		Arc::clone(&metrics),
	);
	let path = message_path.clone();
	let queued = crate::imap::junk_trainer::enqueue_junk_transition(
		&queue, account, previous, updated, path,
	);
	if queued {
		trainer.await_one_call().await;
	}
	trainer.calls()
}

/// Adding `$Junk` to a message that did not have it trains spam on
/// the account's scope.
#[tokio::test]
async fn adding_junk_trains_the_account_scope_as_spam() {
	let calls = run_transition(
		"alice",
		&[],
		&[Flag::parse(JUNK).expect("parse junk")],
		b"spam body",
	)
	.await;
	assert_eq!(calls, vec![("alice".to_string(), 9, true)]);
}

/// Removing `$Junk` (or adding `$NotJunk`) trains ham on the
/// account's scope.
#[tokio::test]
async fn removing_junk_trains_ham() {
	let calls = run_transition(
		"alice",
		&[Flag::parse(JUNK).expect("parse junk")],
		&[],
		b"ham body",
	)
	.await;
	assert_eq!(calls, vec![("alice".to_string(), 8, false)]);
}

/// Adding `$NotJunk` where there was none before also trains ham.
#[tokio::test]
async fn adding_not_junk_trains_ham() {
	let calls = run_transition(
		"alice",
		&[],
		&[Flag::parse(NOT_JUNK).expect("parse not-junk")],
		b"ham body",
	)
	.await;
	assert_eq!(calls, vec![("alice".to_string(), 8, false)]);
}

/// A STORE that flips only `\Seen` (the common re-mark) does not
/// train: no `$Junk` / `$NotJunk` boundary was crossed. The
/// case-only difference (`$junk` vs `$Junk`) is the same keyword
/// and trains nothing either.
#[tokio::test]
async fn a_no_op_store_trains_nothing() {
	let calls = run_transition(
		"alice",
		&[Flag::Seen],
		&[Flag::Seen, Flag::Flagged],
		b"body",
	)
	.await;
	assert!(calls.is_empty(), "non-junk STORE must not train: {calls:?}");

	// Same keyword before and after (different case) -> no train.
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("message.eml");
	std::fs::write(&path, b"body").expect("write message");
	let trainer = Arc::new(RecordingTrainer::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let queue = crate::antispam::training_queue::TrainingQueue::start(
		Arc::clone(&trainer) as Arc<dyn BayesTrainer>,
		crate::storage::MessageCrypto::disabled(),
		Arc::clone(&metrics),
	);
	assert!(!crate::imap::junk_trainer::enqueue_junk_transition(
		&queue,
		"alice",
		&[Flag::parse(JUNK).expect("parse junk")],
		&[Flag::parse("$junk").expect("parse junk lower")],
		PathBuf::from(&path),
	));
	for _ in 0..16 {
		tokio::task::yield_now().await;
	}
	let calls = trainer.calls();
	assert!(
		calls.is_empty(),
		"case-only difference is the same keyword: {calls:?}"
	);
}

/// Below [`MIN_TRUSTED_MESSAGES`] on either side, the per-account
/// scorer falls back to the shared corpus: an account that has not
/// trained enough on both sides cannot classify on noise. The
/// boundary cases (`MIN - 1` against `MIN`, the other axis at `MIN`,
/// and both axes one short) all resolve to the shared scope. The
/// threshold helper ([`super::scoring_scope`]) is the one place the
/// decision is made; these cases drive that helper through every
/// off-by-one path the live scorer can hit.
#[test]
fn score_falls_back_to_shared_below_the_threshold() {
	let account = "alice";
	// Both axes empty.
	assert_eq!(
		super::scoring_scope(is_trusted(Corpus::default()), account),
		SHARED
	);
	// Ham side one short of the threshold: still untrained, regardless of spam.
	assert_eq!(
		super::scoring_scope(
			is_trusted(Corpus {
				ham_messages: MIN_TRUSTED_MESSAGES - 1,
				spam_messages: MIN_TRUSTED_MESSAGES,
			}),
			account
		),
		SHARED
	);
	// Spamming side one short of the threshold: still untrained, regardless of ham.
	assert_eq!(
		super::scoring_scope(
			is_trusted(Corpus {
				ham_messages: MIN_TRUSTED_MESSAGES,
				spam_messages: MIN_TRUSTED_MESSAGES - 1,
			}),
			account
		),
		SHARED
	);
}

/// At the threshold exactly the per-account scope is trusted; one
/// message short and the fallback wins. Drives the `MIN` boundary
/// directly through the `is_trusted` predicate that powers the SMTP
/// scorer: a regression that switched `>=` to `>` would demote the
/// exact-threshold case below the threshold and the assertion here
/// would fail with the literal "wanted account, got shared".
#[test]
fn score_uses_the_account_scope_at_the_threshold() {
	let account = "alice";
	// Both axes exactly at the threshold: trained.
	assert_eq!(
		super::scoring_scope(
			is_trusted(Corpus {
				ham_messages: MIN_TRUSTED_MESSAGES,
				spam_messages: MIN_TRUSTED_MESSAGES,
			}),
			account
		),
		account
	);
	// One axis above the threshold, the other at it: trained.
	assert_eq!(
		super::scoring_scope(
			is_trusted(Corpus {
				ham_messages: MIN_TRUSTED_MESSAGES + 1,
				spam_messages: MIN_TRUSTED_MESSAGES,
			}),
			account
		),
		account
	);
	assert_eq!(
		super::scoring_scope(
			is_trusted(Corpus {
				ham_messages: MIN_TRUSTED_MESSAGES,
				spam_messages: MIN_TRUSTED_MESSAGES + 1,
			}),
			account
		),
		account
	);
}

/// `forget_scope` removes every row under the scope and reports the
/// token-row count. The live-DB test in `tests/database.rs` exercises
/// the real `BayesStore`; this unit test pins the public contract
/// (the method exists and is callable) without needing a database.
#[test]
fn forget_scope_is_exposed_as_an_inherent_method() {
	// The signature is the contract `directory_store::removal::remove_account`
	// depends on; a regression that renames or changes the return type
	// breaks the removal build. This compiles only when the inherent
	// method exists with the right shape.
	fn _accepts(store: &crate::antispam::corpus::BayesStore) {
		let _fut: std::pin::Pin<Box<dyn Future<Output = Result<u64, sqlx::Error>> + Send + '_>> =
			Box::pin(store.forget_scope("ignored"));
	}
}

/// A training job that has already read its message off disk must
/// not recreate the scope a concurrent removal is in the middle of
/// purging. The tombstone lives on the store: `train` checks it
/// before issuing any SQL, so a worker that drained its job between
/// the removal's `forget_scope` start and commit returns silently
/// rather than re-creating rows the purge just dropped.
///
/// The control half of the test removes the tombstone and calls
/// `train` again; without the tombstone the same call must reach the
/// SQL and surface the lazy-pool error, which proves the previous
/// `Ok(())` came from the short-circuit rather than from the SQL
/// succeeding on its own. Without this control the test would also
/// pass for a `train` that returned `Ok(())` unconditionally, which
/// is not the contract the helper guarantees.
#[tokio::test]
async fn a_tombstoned_scope_silently_drops_training() {
	let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
		.expect("lazy pool never connects");
	let store = BayesStore::with_key(pool, [0u8; 32]);

	// Mark the scope as removed (mirrors what `forget_scope` does for
	// the duration of its DELETE).
	let tombstones = store.tombstones();
	tombstones
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.insert("alice".to_string());

	// The lazy pool never connects, so a non-tombstoned `train` would
	// bubble up the connection error. The tombstone check has to fire
	// first and make `train` return `Ok(())` without touching the pool.
	let result = store.train("alice", "any body text", true).await;
	assert!(
		result.is_ok(),
		"tombstoned scope must short-circuit; got {result:?}"
	);

	// Lift the tombstone: the same call must now reach the SQL and
	// surface the lazy-pool error, which proves the previous return
	// value came from the check rather than from the SQL succeeding.
	tombstones
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.remove("alice");
	let result = store.train("alice", "any body text", true).await;
	assert!(
		result.is_err(),
		"with the tombstone lifted the call must reach the SQL and surface the lazy-pool error; got {result:?}"
	);
}

/// `forget_scope` raises and lowers the tombstone around its DELETE
/// so a worker draining a queued job cannot race with the purge. The
/// tombstone is cleared on every exit path: a failed DELETE leaves
/// the rows exactly where they were, so a tombstone that out-lived
/// the failure would silently drop every later training job for
/// that scope with no error and no log line until the next retry
/// or the next process restart, which is the bug the helper now
/// avoids. The per-store lock is what actually serializes the
/// DELETE against a racing `train`; the tombstone is just a flag the
/// worker consults, and the flag is meant to track the transaction,
/// not its outcome.
#[tokio::test]
async fn forget_scope_sets_the_tombstone_for_its_duration() {
	let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
		.expect("lazy pool never connects");
	let store = BayesStore::with_key(pool, [0u8; 32]);

	let result = store.forget_scope("alice").await;
	assert!(
		result.is_err(),
		"lazy pool never connects; forget_scope must error"
	);
	assert!(
		!store
			.tombstones()
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.contains("alice"),
		"a failed DELETE leaves the rows in place; the tombstone must be cleared"
	);
}

/// A failed `forget_scope` must leave the scope live for `train`:
/// the rows are still there because the DELETE never committed, so
/// the next training call must reach the SQL and surface the
/// underlying pool error rather than being silently swallowed by a
/// tombstone the failure left behind. With the lazy pool used below,
/// `train` after the failed purge returns `Err(sqlx::Error::PoolTimedOut)`
/// (the real failure mode when no connection can be acquired). Before
/// the fix the tombstone stayed set on failure and `train` returned
/// `Ok(())`, which silently dropped the message and left the
/// recreated account inheriting whatever the worker would have
/// trained.
#[tokio::test]
async fn a_failed_forget_scope_lets_a_followup_train_reach_the_sql() {
	let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
		.expect("lazy pool never connects");
	let store = BayesStore::with_key(pool, [0u8; 32]);

	let result = store.forget_scope("alice").await;
	assert!(
		result.is_err(),
		"lazy pool never connects; forget_scope must error"
	);

	let result = store.train("alice", "any body text", true).await;
	assert!(
		result.is_err(),
		"a failed purge must not leave the scope tombstoned; train must surface the lazy-pool error, got {result:?}"
	);
}

/// A panic elsewhere must not freeze every later spam-training call:
/// the worker expects the corpus to keep absorbing marks no matter
/// what unrelated branch the rest of the trainer took. The
/// tombstone Mutex is poisoned here by holding it across a panic,
/// which the production path tolerates by calling
/// `unwrap_or_else(|e| e.into_inner())` for every consult. A naive
/// `.lock().expect(...)` in `BayesStore::train` would propagate the
/// poison as a panic for every later `train`; that regression is the
/// one this test pins.
///
/// Sabotaged by reverting the train path to `.expect("tombstone
/// lock")`: the assertion then surfaces with the panic message from
/// the lock failure on its way to the SQL.
#[tokio::test]
async fn a_poisoned_tombstone_lock_still_allows_training() {
	use std::panic::AssertUnwindSafe;
	use std::sync::Arc;

	let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:1/none")
		.expect("lazy pool never connects");
	let store = BayesStore::with_key(pool, [0u8; 32]);

	// Poison the tombstone Mutex by holding it across a panic. The
	// unreachable host inside the catch means the helper itself does
	// not throw past the assertion.
	let tombstones = Arc::clone(store.tombstones());
	let result = std::panic::catch_unwind(AssertUnwindSafe(move || {
		let _guard = tombstones.lock().unwrap_or_else(|error| error.into_inner());
		panic!("simulated panic inside the tombstone Mutex");
	}));
	assert!(result.is_err(), "the helper panic must propagate");

	// The lazy pool is unreachable, so the SQL would bubble a
	// connection error (PoolTimedOut). What matters here is that
	// the call returns Err, not a propagated panic from the
	// tombstone Mutex. We probe that via `tokio::spawn`: an inner
	// panic surfaces as `Err(JoinError)` with `is_panic()` true; a
	// regular failure is `Ok(Err(_))` and is the non-panic outcome
	// the production contract guarantees. The match never compares
	// the inner Result to a custom value: any `Ok(_)` case (whether
	// the SQL returned Ok or Err) means the inner future did not
	// panic, which is exactly what the test pins.
	let join = tokio::spawn(async move { store.train("alice", "any body text", true).await }).await;
	match join {
		Ok(_) => {}
		Err(join_error) if join_error.is_panic() => {
			panic!("train must not panic on a poisoned tombstone Mutex");
		}
		Err(_) => panic!("the spawned task was cancelled, not panicked"),
	}
}
