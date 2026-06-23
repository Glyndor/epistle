//! Trained Bayesian corpus stored in PostgreSQL.
//!
//! Holds the per-token ham/spam counts and message totals that the pure
//! classifier in [`super::bayes`] consumes. Training updates the counts;
//! scoring reads them and delegates the math to `bayes::classify`.
//!
//! Every operation is keyed by a `scope`: a per-account corpus, or the shared
//! corpus [`SHARED`] (`""`) the server trains from its own accept/reject
//! decisions. Scopes are isolated — training one account never affects another.

use std::collections::HashMap;

use sqlx::PgPool;

use super::bayes::{self, Corpus, TokenCounts};

/// The shared corpus scope (the server's own accept/reject learning).
pub const SHARED: &str = "";

/// Train the `scope` corpus on one message: bump the message total and each
/// token's ham or spam count. Runs in a transaction so a message is counted
/// atomically.
pub async fn train(pool: &PgPool, scope: &str, text: &str, spam: bool) -> Result<(), sqlx::Error> {
	let tokens = bayes::tokenize(text);
	let ham_inc: i64 = if spam { 0 } else { 1 };
	let spam_inc: i64 = if spam { 1 } else { 0 };
	let mut tx = pool.begin().await?;

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

/// The trained message totals for `scope` (zero when the scope is untrained).
pub async fn corpus(pool: &PgPool, scope: &str) -> Result<Corpus, sqlx::Error> {
	let row = sqlx::query!(
		"SELECT ham_messages, spam_messages FROM bayes_corpus WHERE scope = $1",
		scope,
	)
	.fetch_optional(pool)
	.await?;
	Ok(row.map_or(Corpus::default(), |r| Corpus {
		ham_messages: r.ham_messages.max(0) as u64,
		spam_messages: r.spam_messages.max(0) as u64,
	}))
}

/// Fetch counts for the given tokens in `scope` in one query; absent tokens are
/// omitted.
async fn counts_for(
	pool: &PgPool,
	scope: &str,
	tokens: &[String],
) -> Result<HashMap<String, TokenCounts>, sqlx::Error> {
	let rows = sqlx::query!(
		"SELECT token, ham_count, spam_count FROM bayes_token \
		 WHERE scope = $1 AND token = ANY($2)",
		scope,
		tokens,
	)
	.fetch_all(pool)
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
pub async fn score(pool: &PgPool, scope: &str, text: &str) -> Result<f64, sqlx::Error> {
	let tokens = bayes::tokenize(text);
	let corpus = corpus(pool, scope).await?;
	let counts = counts_for(pool, scope, &tokens).await?;
	Ok(bayes::classify(
		&tokens,
		|token| counts.get(token).copied().unwrap_or_default(),
		corpus,
	))
}

/// Train the `scope` corpus in the background, logging on failure. Used on the
/// delivery path so learning never blocks or fails mail.
pub fn train_in_background(pool: PgPool, scope: String, text: String, spam: bool) {
	tokio::spawn(async move {
		if let Err(error) = train(&pool, &scope, &text, spam).await {
			tracing::warn!(%error, "bayes training failed");
		}
	});
}
