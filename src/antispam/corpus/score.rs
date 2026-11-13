//! Score a message against a corpus, pick which corpus an account is scored
//! on, and the [`BayesScorer`] the SMTP path consults.

use std::collections::HashMap;

use crate::antispam::bayes::{self, Corpus, TokenCounts};
use crate::antispam::scoring_text::scoring_text;
use crate::antispam::shared_training::TrainSource;

use super::{BayesStore, CAPPED_SCORE_FLOOR, MAX_SCORE_TOKENS, SCORE_POSITIONAL, SHARED};

impl BayesStore {
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
	/// what a person reads (see [`crate::antispam::scoring_text`]): the
	/// headers and the text parts, not the attachments, cut to a window. A
	/// message that did not fit in the window is scored like one with too
	/// many words.
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

	/// Whether `scope` holds enough ham and spam to be scored on its own
	/// (see [`crate::antispam::trainer::is_trusted`]).
	pub async fn is_trained(&self, scope: &str) -> Result<bool, sqlx::Error> {
		Ok(crate::antispam::trainer::is_trusted(
			self.corpus(scope).await?,
		))
	}
}

/// Pick the scope the per-account scorer should consult: the account's
/// own corpus when it has reached the trusted threshold on both sides,
/// the shared corpus otherwise. The decision lives in its own helper
/// so the boundary conditions are unit-testable without a database;
/// the SMTP hot path calls [`BayesStore::score_for_account`](crate::antispam::trainer::BayesTrainer::score_for_account), which
/// delegates here.
pub fn scoring_scope(trained: bool, account: &str) -> &str {
	if trained { account } else { SHARED }
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
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>>;

	/// Whether `scope` has accumulated enough ham and spam messages for
	/// the threshold-based decisions to trust a score it returns. The
	/// default returns `true` so a fake scorer wires in without writing
	/// database shims; the production `BayesStore` gates on
	/// [`crate::antispam::trainer::MIN_TRUSTED_MESSAGES`] on either side.
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
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		crate::antispam::trainer::BayesTrainer::score_for_account(self, account, text)
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
