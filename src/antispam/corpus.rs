//! Trained Bayesian corpus stored in PostgreSQL.
//!
//! Holds the per-token ham/spam counts and message totals that the pure
//! classifier in [`super::bayes`] consumes. Training updates the counts;
//! scoring reads them and delegates the math to `bayes::classify`.
//!
//! Every operation is keyed by a `scope`: a per-account corpus, or the shared
//! corpus [`SHARED`] (`""`) the server trains from its own accept/reject
//! decisions. Scopes are isolated — training one account never affects another.
//!
//! **Encryption at rest:** tokens are never stored in clear. Each token is
//! replaced by a keyed HMAC-SHA256 of its text under a per-instance key held in
//! a `0600` file outside the database, so a database compromise reveals neither
//! the words users received nor what they marked as spam — only opaque,
//! per-instance hashes. The hash is deterministic, so lookups still work, and
//! token identity (all the classifier needs) is preserved.

use std::collections::HashMap;
use std::path::Path;

use sqlx::PgPool;

use super::bayes::{self, Corpus, TokenCounts};
use crate::storage::load_or_create_key_file;

/// The shared corpus scope (the server's own accept/reject learning).
pub const SHARED: &str = "";

/// The corpus key filename under the data directory.
const KEY_FILE: &str = "bayes-corpus.key";

/// A PostgreSQL-backed Bayesian corpus that stores tokens as keyed hashes.
#[derive(Clone)]
pub struct BayesStore {
	pool: PgPool,
	key: [u8; 32],
}

impl BayesStore {
	/// Open the store, loading the token key from `data_dir` or generating and
	/// persisting a fresh `0600` key on first use.
	pub fn open(pool: PgPool, data_dir: &Path) -> std::io::Result<Self> {
		let key = load_or_create_key_file(data_dir, KEY_FILE)?;
		Ok(BayesStore { pool, key })
	}

	/// Build a store with an explicit key (tests).
	pub fn with_key(pool: PgPool, key: [u8; 32]) -> Self {
		BayesStore { pool, key }
	}

	/// The stored (hashed) form of a token.
	fn hash(&self, token: &str) -> String {
		hash_token(&self.key, token)
	}

	/// Train the `scope` corpus on one message: bump the message total and each
	/// token's ham or spam count, atomically.
	pub async fn train(&self, scope: &str, text: &str, spam: bool) -> Result<(), sqlx::Error> {
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
	/// The probability a message is spam, in `[0, 1]`. A `score` of `0.5`
	/// with no LLM verdict to lean on is the case SubjectPass is built for.
	fn score<'a>(
		&'a self,
		scope: &'a str,
		text: &'a str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<f64, sqlx::Error>> + Send + 'a>>;

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

	fn train(&self, scope: &str, text: &str, spam: bool) {
		self.train_in_background(scope.to_string(), text.to_string(), spam);
	}
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;
