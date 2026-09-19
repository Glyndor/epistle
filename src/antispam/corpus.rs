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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;

use super::bayes::{self, Corpus, TokenCounts};
use super::trainer::{BayesTrainer, TrainerFuture};
use crate::storage::load_or_create_key_file;

/// The shared corpus scope (the server's own accept/reject learning).
pub const SHARED: &str = "";

/// The corpus key filename under the data directory.
const KEY_FILE: &str = "bayes-corpus.key";

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
	pool: PgPool,
	key: [u8; 32],
	/// Scopes whose removal is currently happening, or has just
	/// committed, so a training worker that has already read its
	/// message off disk drops the job rather than recreating the
	/// rows the purge is dropping. See [`BayesStore::train`].
	tombstones: TombstoneSet,
	/// Serializes `train` and `forget_scope` against each other within
	/// this process so a worker that passed the tombstone check cannot
	/// race the DELETE commit. Training is infrequent, so holding it
	/// across the SQL is a fine trade for closing the window the
	/// tombstone set alone cannot. The Mutex is per-instance: a removal
	/// run from the CLI does not see the server's training worker
	/// (different processes, different Mutexes); the cross-process
	/// limit is named on [`BayesStore::forget_scope`].
	scope_lock: Arc<tokio::sync::Mutex<()>>,
}

impl BayesStore {
	/// Open the store, loading the token key from `data_dir` or generating and
	/// persisting a fresh `0600` key on first use.
	pub fn open(pool: PgPool, data_dir: &Path) -> std::io::Result<Self> {
		let key = load_or_create_key_file(data_dir, KEY_FILE)?;
		Ok(BayesStore {
			pool,
			key,
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
		})
	}

	/// Build a store with an explicit key (tests). The tombstone set
	/// starts empty: callers can populate it through [`BayesStore::tombstones`]
	/// when they want to simulate an in-flight removal.
	pub fn with_key(pool: PgPool, key: [u8; 32]) -> Self {
		BayesStore {
			pool,
			key,
			tombstones: new_tombstone_set(),
			scope_lock: Arc::new(tokio::sync::Mutex::new(())),
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
	fn hash(&self, token: &str) -> String {
		hash_token(&self.key, token)
	}

	/// Train the `scope` corpus on one message: bump the message total and each
	/// token's ham or spam count, atomically.
	pub async fn train(&self, scope: &str, text: &str, spam: bool) -> Result<(), sqlx::Error> {
		// Hold the per-store lock for the duration of every train call so a
		// worker that just passed the tombstone check cannot race the DELETE a
		// concurrent `forget_scope` is committing. Training is infrequent, so
		// holding the lock across the SQL is fine; the lock is per-instance
		// and does not span processes.
		let _scope_guard = self.scope_lock.lock().await;
		// A scope whose removal is in flight (or has just committed and
		// the tombstone has not yet been cleared) is on its way out:
		// training now would recreate rows the purge is dropping. Drop
		// the job silently so the worker's caller never sees an error
		// for a message that no longer belongs to a live account. The
		// lock is taken with `unwrap_or_else(|e| e.into_inner())` so a
		// panic inside another train call does not poison every later
		// spam-learning job through the worker.
		if self
			.tombstones
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.contains(scope)
		{
			return Ok(());
		}
		let tokens: Vec<String> = bayes::tokenize(text).iter().map(|t| self.hash(t)).collect();
		let ham_inc: i64 = if spam { 0 } else { 1 };
		let spam_inc: i64 = if spam { 1 } else { 0 };
		let mut tx = self.pool.begin().await?;

		sqlx::query!(
			"INSERT INTO bayes_corpus (scope, ham_messages, spam_messages) \
			 VALUES ($1, $2, $3) \
			 ON CONFLICT (scope) DO UPDATE SET \
			     ham_messages = bayes_corpus.ham_messages + $2, \
			     spam_messages = bayes_corpus.spam_messages + $3, \
			     updated_at = now()",
			scope,
			ham_inc,
			spam_inc,
		)
		.execute(&mut *tx)
		.await?;

		for token in tokens {
			sqlx::query!(
				"INSERT INTO bayes_token (id, scope, token, ham_count, spam_count) \
				 VALUES ($1, $2, $3, $4, $5) \
				 ON CONFLICT (scope, token) DO UPDATE SET \
				     ham_count = bayes_token.ham_count + $4, \
				     spam_count = bayes_token.spam_count + $5, \
				     updated_at = now()",
				uuid::Uuid::now_v7(),
				scope,
				token,
				ham_inc,
				spam_inc,
			)
			.execute(&mut *tx)
			.await?;
		}
		tx.commit().await
	}

	/// Train in the background, logging on failure. Used on the delivery path so
	/// learning never blocks or fails mail.
	pub fn train_in_background(&self, scope: String, text: String, spam: bool) {
		let store = self.clone();
		tokio::spawn(async move {
			if let Err(error) = store.train(&scope, &text, spam).await {
				tracing::warn!(%error, "bayes training failed");
			}
		});
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

	/// Score `text` as spam in `[0, 1]` using the `scope` corpus.
	pub async fn score(&self, scope: &str, text: &str) -> Result<f64, sqlx::Error> {
		let plain = bayes::tokenize(text);
		let hashed: Vec<String> = plain.iter().map(|t| self.hash(t)).collect();
		let corpus = self.corpus(scope).await?;
		let counts = self.counts_for(scope, &hashed).await?;
		// Map each plaintext token to its hashed counts for the classifier.
		let by_hash: HashMap<&str, &str> = plain
			.iter()
			.zip(hashed.iter())
			.map(|(p, h)| (p.as_str(), h.as_str()))
			.collect();
		Ok(bayes::classify(
			&plain,
			|token| {
				by_hash
					.get(token)
					.and_then(|h| counts.get(*h))
					.copied()
					.unwrap_or_default()
			},
			corpus,
		))
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
	/// tombstone is only cleared when the transaction commits, so a
	/// worker that has already read its message but has not yet reached
	/// `train` will see the tombstone and drop the job. The whole call
	/// also holds the per-store serialization lock for its duration, so
	/// a worker that passed the tombstone check is serialized against
	/// the DELETE itself: the INSERT and the DELETE cannot interleave
	/// inside this process. Training is infrequent, so holding the
	/// lock across the transaction is cheap.
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
	///
	/// A failed DELETE keeps the tombstone in place: the absent rows are
	/// still absent and the only thing that would recreate them is a
	/// new training call, which we are correct to suppress until the
	/// next retry commits.
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
		if result.is_ok() {
			self.tombstones
				.lock()
				.unwrap_or_else(|error| error.into_inner())
				.remove(scope);
		}
		result
	}

	async fn forget_scope_inner(&self, scope: &str) -> Result<u64, sqlx::Error> {
		let mut tx = self.pool.begin().await?;
		let tokens = sqlx::query!("DELETE FROM bayes_token WHERE scope = $1", scope,)
			.execute(&mut *tx)
			.await?
			.rows_affected();
		sqlx::query!("DELETE FROM bayes_corpus WHERE scope = $1", scope,)
			.execute(&mut *tx)
			.await?;
		tx.commit().await?;
		Ok(tokens)
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
			let text = String::from_utf8_lossy(&text);
			if let Err(error) = BayesStore::train(self, account, &text, spam).await {
				tracing::warn!(account, %error, "per-account bayes training failed");
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
					tracing::warn!(account, %error, "per-account bayes trained lookup failed");
					return None;
				}
			};
			let scope = scoring_scope(trained, account);
			let text = String::from_utf8_lossy(text);
			match self.score(scope, &text).await {
				Ok(score) => Some(score),
				Err(error) => {
					tracing::warn!(account, %error, "per-account bayes score failed");
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
fn hash_token(key: &[u8], token: &str) -> String {
	let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
	let tag = ring::hmac::sign(&mac, token.as_bytes());
	tag.as_ref().iter().fold(String::new(), |mut acc, byte| {
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

	/// Train the corpus on `text` as ham (`spam = false`) or spam. The
	/// default implementation is a no-op so a fake scoring source does not
	/// need to back a database.
	fn train(&self, _scope: &str, _text: &str, _spam: bool) {}
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

	fn train(&self, scope: &str, text: &str, spam: bool) {
		self.train_in_background(scope.to_string(), text.to_string(), spam);
	}
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;
