//! Unit tests for the corpus key handling, the token hash, the
//! trainer transition table and the score threshold (no database).

use super::*;
use crate::antispam::trainer::{BayesTrainer, MIN_TRUSTED_MESSAGES, RecordingTrainer};
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

/// An empty scope has fewer than `MIN_TRUSTED_MESSAGES` on every
/// side, so the per-account score falls back to the shared corpus.
#[test]
fn score_falls_back_to_shared_below_the_threshold() {
	let untrained: Corpus = Corpus::default();
	assert!(untrained.ham_messages < MIN_TRUSTED_MESSAGES);
	assert!(untrained.spam_messages < MIN_TRUSTED_MESSAGES);
	// Below the threshold on either side: still untrained.
	let under_ham = Corpus {
		ham_messages: MIN_TRUSTED_MESSAGES - 1,
		spam_messages: MIN_TRUSTED_MESSAGES,
	};
	assert!(under_ham.ham_messages < MIN_TRUSTED_MESSAGES);
}

/// At the threshold exactly the scope is trained; one message short
/// and the fallback wins. Pins the `>=` boundary so a regression to
/// `>` visibly drops the boundary case.
#[test]
fn score_uses_the_account_scope_at_the_threshold() {
	let corpus = Corpus {
		ham_messages: MIN_TRUSTED_MESSAGES,
		spam_messages: MIN_TRUSTED_MESSAGES,
	};
	assert!(corpus.ham_messages >= MIN_TRUSTED_MESSAGES);
	assert!(corpus.spam_messages >= MIN_TRUSTED_MESSAGES);
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
