//! Trained Bayesian corpus stored in PostgreSQL.
//!
//! Holds the per-token ham/spam counts and message totals that the pure
//! classifier in [`super::bayes`] consumes. Training updates the counts;
//! scoring reads them and delegates the math to `bayes::classify`.
//!
//! Every operation is keyed by a `scope`: a per-account corpus, or the shared
//! corpus [`SHARED`] (`""`) the server trains from its own accept/reject
//! decisions. Scopes are isolated: training one account never affects another.
//!
//! **Encryption at rest:** tokens are never stored in clear. Each token is
//! replaced by a keyed HMAC-SHA256 of its text under a per-instance key held in
//! a `0600` file outside the database, so a database compromise reveals neither
//! the words users received nor what they marked as spam, only opaque,
//! per-instance hashes. The hash is deterministic, so lookups still work, and
//! token identity (all the classifier needs) is preserved.
//!
//! **Bounded work.** Training is fed by mail any remote sender can send, so one
//! message costs a fixed amount whatever its size: [`BayesStore::train`] reads
//! a window of [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES) of the text, keeps at most
//! [`MAX_TRAIN_TOKENS`] distinct tokens and writes them in one statement. The
//! SMTP path does not call it directly: [`BayesStore::submit_training`] queues
//! the job for a small, fixed set of workers (see [`super::shared_training`]).
//!
//! **Lock order.** Every transaction that takes more than one of these locks
//! takes them in this order, so two of them cannot wait for each other (a
//! process-local `scope_lock` first, then rows in the database):
//! `scope_lock`, then `bayes_corpus`, then `bayes_token`. Whatever must be
//! locked before the totals (a per-account ledger of lessons, for instance)
//! comes before `bayes_corpus`. Inside `bayes_token` the rows are written in
//! ascending token order. [`BayesStore::forget_scope`] follows the same order.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use sqlx::PgPool;

use super::bayes::{self, Corpus, TokenCounts};
use super::scoring_text::scoring_text;
use super::shared_training::{SharedTraining, TrainSource};
use super::learning::LearnOutcome;
use super::trainer::{BayesTrainer, TrainerFuture};
use crate::storage::load_or_create_key_file;

/// The shared corpus scope (the server's own accept/reject learning).
pub const SHARED: &str = "";

/// The corpus key filename under the data directory.
const KEY_FILE: &str = "bayes-corpus.key";

/// The most distinct tokens one message adds to a corpus. Also the cap a
/// user's junk lesson is held to; a message with more distinct words than
/// this has told the corpus all it will learn from the words it opens with.
pub const MAX_TRAIN_TOKENS: usize = 5000;

/// The most distinct tokens one message is scored on, from the same window of
/// its text as training. The classifier keeps the few most telling tokens, so
/// a message under this and the window scores exactly as it always did; scoring
/// runs inline in the session of an unauthenticated sender, so a larger one
/// cannot cost more.
pub const MAX_SCORE_TOKENS: usize = 5000;

/// Of those, the first and the last this many distinct tokens of the window
/// are always read when there are more than the cap: where a message says what
/// it is. The rest are chosen by a keyed hash.
pub const SCORE_POSITIONAL: usize = 1000;

/// The lowest score a message gets when it holds more distinct tokens than
/// [`MAX_SCORE_TOKENS`]: neither clean nor spam. Such a message is scored on a
/// sample of its words, which is what someone who wants to hide spam in a
/// pile of filler hopes for, so it never counts as a message the corpus is
/// sure is ham, and falls in the band where a second opinion is asked.
pub const CAPPED_SCORE_FLOOR: f64 = 0.5;

/// The set of scope names whose removal is in flight or whose purge has
/// just committed. The training worker consults the set before any
/// `INSERT` so a job that drained between a removal's start and its
/// commit cannot recreate rows the purge is dropping. The handle is
/// shared with every clone of the [`BayesStore`] so all training paths
/// see the same state.
pub type TombstoneSet = Arc<Mutex<HashSet<String>>>;

/// A fresh, empty tombstone set for tests and constructors that have
/// no other source of one.
pub fn new_tombstone_set() -> TombstoneSet {
	Arc::new(Mutex::new(HashSet::new()))
}

/// A PostgreSQL-backed Bayesian corpus that stores tokens as keyed hashes.
#[derive(Clone)]
pub struct BayesStore {
	pub(super) pool: PgPool,
	/// The keyed hash of tokens, built once from the instance key.
	pub(super) mac: ring::hmac::Key,
	/// Scopes whose removal is currently happening, or has just
	/// committed, so a training worker that has already read its
	/// message off disk drops the job rather than recreating the
	/// rows the purge is dropping. See [`BayesStore::train`].
	pub(super) tombstones: TombstoneSet,
	/// Serializes `train` and `forget_scope` against each other within
	/// this process so a worker that passed the tombstone check cannot
	/// race the DELETE commit. Training is infrequent, so holding it
	/// across the SQL is a fine trade for closing the window the
	/// tombstone set alone cannot. The Mutex is per-instance: a removal
	/// run from the CLI does not see the server's training worker
	/// (different processes, different Mutexes); the cross-process
	/// limit is named on [`BayesStore::forget_scope`].
	pub(super) scope_lock: Arc<tokio::sync::Mutex<()>>,
	/// The queue and workers that train the shared corpus from SMTP,
	/// started by the first job. Clones share it.
	shared: Arc<OnceLock<SharedTraining>>,
}

impl BayesStore {
	/// Open the store, loading the token key from `data_dir` or generating and
	/// persisting a fresh `0600` key on first use.
	pub fn open(pool: PgPool, data_dir: &Path) -> std::io::Result<Self> {
		let key = load_or_create_key_file(data_dir, KEY_FILE)?;
		Ok(BayesStore {
			pool,
			mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
			shared: Arc::new(OnceLock::new()),
		})
	}

	/// Build a store with an explicit key (tests). The tombstone set
	/// starts empty: callers can populate it through [`BayesStore::tombstones`]
	/// when they want to simulate an in-flight removal.
	pub fn with_key(pool: PgPool, key: [u8; 32]) -> Self {
		BayesStore {
			pool,
			mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
			shared: Arc::new(OnceLock::new()),
		}
	}

	/// This store without the shared-training queue: same pool, key,
	/// tombstones and lock. The workers hold one, so that the queue's
	/// sender is not kept alive by the workers it feeds.
	fn detached(&self) -> Self {
		BayesStore {
			pool: self.pool.clone(),
			mac: self.mac.clone(),
			tombstones: self.tombstones.clone(),
			scope_lock: self.scope_lock.clone(),
			shared: Arc::new(OnceLock::new()),
		}
	}

	/// The shared tombstone set the training worker consults before
	/// every INSERT. Production keeps the set empty except inside
	/// [`BayesStore::forget_scope`]; tests use it to drive the
	/// race-condition test above without a database.
	pub fn tombstones(&self) -> &TombstoneSet {
		&self.tombstones
	}

	/// The stored (hashed) form of a token.
	pub(super) fn hash(&self, token: &str) -> String {
		hex(&self.tag(token))
	}

	/// The keyed fingerprint of a token, the raw bytes of [`BayesStore::hash`].
	fn tag(&self, token: &str) -> bayes::TokenTag {
		let tag = ring::hmac::sign(&self.mac, token.as_bytes());
		let mut out = [0u8; 32];
		out.copy_from_slice(tag.as_ref());
		out
	}

	/// Queue one message for the shared corpus and return whether it was
	/// accepted. Never waits and never fails the caller: a source over its
	/// share, a full queue or an untracked source (see
	/// [`super::shared_training`]) drops the job and returns `false`. Must be
	/// called from inside a tokio runtime.
	pub fn submit_training(
		&self,
		source: &TrainSource,
		scope: &str,
		data: &[u8],
		spam: bool,
	) -> bool {
		self.shared
			.get_or_init(|| SharedTraining::start(self.detached()))
			.submit(source, scope, data, spam)
	}

	/// Train in the background without a named source, logging on failure.
	/// The job goes through the same bounded queue as
	/// [`BayesStore::submit_training`]; the queue and its workers bound it,
	/// no source budget applies.
	pub fn train_in_background(&self, scope: String, text: String, spam: bool) {
		self.submit_training(&TrainSource::unattributed(), &scope, text.as_bytes(), spam);
	}

	/// The trained message totals for `scope` (zero when untrained).
	pub async fn corpus(&self, scope: &str) -> Result<Corpus, sqlx::Error> {
		let row = sqlx::query!(
			"SELECT ham_messages, spam_messages FROM bayes_corpus WHERE scope = $1",
			scope,
		)
		.fetch_optional(&self.pool)
		.await?;
		Ok(row.map_or(Corpus::default(), |r| Corpus {
			ham_messages: r.ham_messages.max(0) as u64,
			spam_messages: r.spam_messages.max(0) as u64,
		}))
	}

	/// Counts for the given (already-hashed) tokens in `scope`.
	async fn counts_for(
		&self,
		scope: &str,
		hashed: &[String],
	) -> Result<HashMap<String, TokenCounts>, sqlx::Error> {
		let rows = sqlx::query!(
			"SELECT token, ham_count, spam_count FROM bayes_token \
			 WHERE scope = $1 AND token = ANY($2)",
			scope,
			hashed,
		)
		.fetch_all(&self.pool)
		.await?;
		Ok(rows
			.into_iter()
			.map(|r| {
				(
					r.token,
					TokenCounts {
						ham: r.ham_count.max(0) as u64,
						spam: r.spam_count.max(0) as u64,
					},
				)
			})
			.collect())
	}

	/// Score `text` as spam in `[0, 1]` using the `scope` corpus, from the
	/// first and last 128 KiB of it and at most [`MAX_SCORE_TOKENS`] distinct
	/// tokens, in one query. A message with more distinct tokens than that
	/// is scored on a keyed sample of them and never below
	/// [`CAPPED_SCORE_FLOOR`]. A message under both bounds scores on all of it.
	pub async fn score(&self, scope: &str, text: &str) -> Result<f64, sqlx::Error> {
		self.score_text(scope, text, false).await
	}

	/// Score a raw message the way the SMTP server does: reduced first to
	/// what a person reads (see [`super::scoring_text`]): the headers and the
	/// text parts, not the attachments, cut to a window. A message that
	/// did not fit in the window is scored like one with too many words.
	pub async fn score_message(&self, scope: &str, raw: &[u8]) -> Result<f64, sqlx::Error> {
		let reduced = scoring_text(raw);
		self.score_text(scope, &reduced.text, reduced.clipped).await
	}

	/// [`BayesStore::score`] for text that may already have been cut to a
	/// window by the caller (`clipped`).
	async fn score_text(&self, scope: &str, text: &str, clipped: bool) -> Result<f64, sqlx::Error> {
		// A window of the text and a cap on distinct tokens, applied before
		// anything is hashed or looked up (see [`MAX_SCORE_TOKENS`]).
		let tokens = self.window_tokens(text, MAX_SCORE_TOKENS, SCORE_POSITIONAL);
		let capped = tokens.capped || clipped;
		let plain = tokens.plain;
		let hashed: Vec<String> = plain.iter().map(|t| self.hash(t)).collect();
		let corpus = self.corpus(scope).await?;
		let counts = self.counts_for(scope, &hashed).await?;
		// Map each plaintext token to its hashed counts for the classifier.
		let by_hash: HashMap<&str, &str> = plain
			.iter()
			.zip(hashed.iter())
			.map(|(p, h)| (p.as_str(), h.as_str()))
			.collect();
		let score = bayes::classify(
			&plain,
			|token| {
				by_hash
					.get(token)
					.and_then(|h| counts.get(*h))
					.copied()
					.unwrap_or_default()
			},
			corpus,
		);
		Ok(if capped {
			score.max(CAPPED_SCORE_FLOOR)
		} else {
			score
		})
	}

	/// Train the `scope` corpus on the raw message `raw`, reduced first to what
	/// is read of it (see [`super::scoring_text`]). A message that could not be
	/// reduced has no words to count, and teaches nothing: `Ok(false)`.
	pub async fn train_message(
		&self,
		scope: &str,
		raw: &[u8],
		spam: bool,
	) -> Result<bool, sqlx::Error> {
		let reduced = scoring_text(raw);
		if reduced.unread {
			tracing::warn!("a message that could not be read was not learned from");
			return Ok(false);
		}
		self.train(scope, &reduced.text, spam).await?;
		Ok(true)
	}

	/// Whether `scope` holds enough ham and spam to be scored on its own
	/// (see [`super::trainer::is_trusted`]).
	pub async fn is_trained(&self, scope: &str) -> Result<bool, sqlx::Error> {
		Ok(super::trainer::is_trusted(self.corpus(scope).await?))
	}

	/// Drop every row of `scope`: the message totals and every token
	/// count, in one transaction. Returns the number of token rows
	/// removed. Account removal calls it so a recreated account name
	/// does not inherit the previous user's training.
	///
	/// The scope is tombstoned before the transaction starts and the
	/// tombstone is cleared when the transaction finishes, success or
	/// failure: the row cannot have been dropped if the DELETE
	/// returned an error, so a tombstone that out-lived the failure
	/// would silently drop every later training job for that scope
	/// with no error and no log line. The window the tombstone covers
	/// is the transaction itself, which the per-store serialization
	/// lock already holds for the same span, so within this process the
	/// INSERT and the DELETE cannot interleave: a worker that drained
	/// its job between the removal's start and its commit either
	/// reaches `train` while the lock is held (and queues until the
	/// DELETE is done) or reaches it after the lock is released (and
	/// sees the cleared tombstone). Training is infrequent, so holding
	/// the lock across the transaction is cheap.
	///
	/// **Known limit, per process.** The lock is per
	/// [`BayesStore`] instance and shared across its clones, so two
	/// processes do not see each other's lock: a `mail account-remove`
	/// run while the `serve` process is alive does not coordinate with
	/// the server's training worker. Cross-process removal therefore
	/// still relies on a concurrent `serve` not having training jobs in
	/// flight for the same account; in practice the server has already
	/// dropped the message files for any purged user, but the
	/// coordination is the operator's, not the helper's.
	pub async fn forget_scope(&self, scope: &str) -> Result<u64, sqlx::Error> {
		let _scope_guard = self.scope_lock.lock().await;
		{
			let mut tombstones = self
				.tombstones
				.lock()
				.unwrap_or_else(|error| error.into_inner());
			tombstones.insert(scope.to_string());
		}
		let result = self.forget_scope_inner(scope).await;
		self.tombstones
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.remove(scope);
		result
	}

	async fn forget_scope_inner(&self, scope: &str) -> Result<u64, sqlx::Error> {
		self.purge_scope(scope).await
	}
}

impl BayesTrainer for BayesStore {
	fn train<'a>(&'a self, account: &'a str, text: Vec<u8>, spam: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async move {
			// A user mark never trains the shared scope: that one learns
			// from the server's own accept and reject decisions.
			if account == SHARED {
				return;
			}
			if let Err(error) = self.train_message(account, &text, spam).await {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"per-account bayes training failed"
				);
			}
		})
	}

	fn learn<'a>(
		&'a self,
		account: &'a str,
		text: Vec<u8>,
		spam: bool,
	) -> TrainerFuture<'a, LearnOutcome> {
		Box::pin(async move {
			match BayesStore::learn(self, account, &text, spam).await {
				Ok(outcome) => outcome,
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes learning failed"
					);
					LearnOutcome::Failed
				}
			}
		})
	}

	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		text: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>> {
		Box::pin(async move {
			let trained = match self.is_trained(account).await {
				Ok(trained) => trained,
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes trained lookup failed"
					);
					return None;
				}
			};
			let scope = scoring_scope(trained, account);
			match self.score_message(scope, text).await {
				Ok(score) => Some(score),
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes score failed"
					);
					None
				}
			}
		})
	}
}

/// Pick the scope the per-account scorer should consult: the account's
/// own corpus when it has reached the trusted threshold on both sides,
/// the shared corpus otherwise. The decision lives in its own helper
/// so the boundary conditions are unit-testable without a database;
/// the SMTP hot path calls [`BayesStore::score_for_account`], which
/// delegates here.
pub fn scoring_scope(trained: bool, account: &str) -> &str {
	if trained { account } else { SHARED }
}

/// The stored form of a token: a keyed HMAC-SHA256, hex-encoded. Deterministic
/// (so lookups work) but irreversible without the key (so a database leak does
/// not reveal the words).
#[cfg(test)]
fn hash_token(key: &[u8], token: &str) -> String {
	let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
	hex(ring::hmac::sign(&mac, token.as_bytes()).as_ref())
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	})
}

/// A pluggable scoring source for the uncertain band. The production
/// implementation is [`BayesStore`]; tests use a small in-memory fake that
/// returns a deterministic score so the SMTP path can be exercised
/// without a database. The trait stays narrow (one async method, no
/// lifetimes) so a `dyn BayesScorer` is cheap to share across listeners.
pub trait BayesScorer: Send + Sync {
	/// The probability a message is spam in `scope` (the shared corpus or a
	/// per-account one), in `[0, 1]`. A `score` of `0.5` with no LLM verdict
	/// to lean on is the case SubjectPass is built for.
	fn score<'a>(
		&'a self,
		scope: &'a str,
		text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>;

	/// The probability a message is spam for the per-account scope keyed by
	/// `account`. Falls back to the shared scope while the account is below
	/// the trusted training threshold; returns `None` when the score could
	/// not be computed (DB hiccup, scope lookup failed). The SMTP server uses
	/// this to score inbound mail against the recipient's own training.
	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		text: &'a [u8],
	) -> super::trainer::TrainerFuture<'a, Option<f64>>;

	/// Whether `scope` has accumulated enough ham and spam messages for
	/// the threshold-based decisions to trust a score it returns. The
	/// default returns `true` so a fake scorer wires in without writing
	/// database shims; the production `BayesStore` gates on
	/// [`super::trainer::MIN_TRUSTED_MESSAGES`] on either side.
	fn is_trusted<'a>(
		&'a self,
		scope: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
		let _ = scope;
		Box::pin(async move { true })
	}

	/// Train the corpus on `text` as ham (`spam = false`) or spam. The
	/// default implementation is a no-op so a fake scoring source does not
	/// need to back a database.
	fn train(&self, _scope: &str, _text: &str, _spam: bool) {}

	/// Train the shared corpus on one inbound message from `source`, the
	/// way the SMTP server learns from its own decisions. Returns whether
	/// the job was accepted; `false` means it was dropped (the source is
	/// over its share, or the queue is full) and the caller counts it. The
	/// default forwards to [`BayesScorer::train`] and accepts everything,
	/// which keeps a fake scorer cheap to wire in.
	fn train_from(&self, source: &TrainSource, data: &[u8], spam: bool) -> bool {
		let _ = source;
		self.train(SHARED, &String::from_utf8_lossy(data), spam);
		true
	}
}

impl BayesScorer for BayesStore {
	fn score<'a>(
		&'a self,
		scope: &'a str,
		text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>
	{
		Box::pin(async move { BayesStore::score(self, scope, text).await })
	}

	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		text: &'a [u8],
	) -> super::trainer::TrainerFuture<'a, Option<f64>> {
		super::trainer::BayesTrainer::score_for_account(self, account, text)
	}

	fn is_trusted<'a>(
		&'a self,
		scope: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
		Box::pin(async move {
			match BayesStore::is_trained(self, scope).await {
				Ok(trusted) => trusted,
				Err(error) => {
					tracing::warn!(
						scope,
						%error,
						"bayes trained-lookup failed; treating as untrusted"
					);
					false
				}
			}
		})
	}

	fn train(&self, scope: &str, text: &str, spam: bool) {
		self.train_in_background(scope.to_string(), text.to_string(), spam);
	}

	fn train_from(&self, source: &TrainSource, data: &[u8], spam: bool) -> bool {
		self.submit_training(source, SHARED, data, spam)
	}
}

#[path = "corpus_train.rs"]
mod train;

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;
