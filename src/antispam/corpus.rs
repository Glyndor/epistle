//! Trained Bayesian corpus stored in PostgreSQL.
//!
//! Holds the per-token ham/spam counts and message totals that the pure
//! classifier in [`super::bayes`] consumes. Training updates the counts;
//! scoring reads them and delegates the math to `bayes::classify`.

use std::collections::HashMap;

use sqlx::PgPool;

use super::bayes::{self, Corpus, TokenCounts};

/// Train the corpus on one message: bump the message total and each token's
/// ham or spam count. Runs in a transaction so a message is counted atomically.
pub async fn train(pool: &PgPool, text: &str, spam: bool) -> Result<(), sqlx::Error> {
	let tokens = bayes::tokenize(text);
	let mut tx = pool.begin().await?;

	if spam {
		sqlx::query!(
			"UPDATE bayes_corpus SET spam_messages = spam_messages + 1, updated_at = now()"
		)
		.execute(&mut *tx)
		.await?;
	} else {
		sqlx::query!("UPDATE bayes_corpus SET ham_messages = ham_messages + 1, updated_at = now()")
			.execute(&mut *tx)
			.await?;
	}

	let ham_inc: i64 = if spam { 0 } else { 1 };
	let spam_inc: i64 = if spam { 1 } else { 0 };
	for token in tokens {
		sqlx::query!(
			"INSERT INTO bayes_token (id, token, ham_count, spam_count) \
			 VALUES ($1, $2, $3, $4) \
			 ON CONFLICT (token) DO UPDATE SET \
			     ham_count = bayes_token.ham_count + $3, \
			     spam_count = bayes_token.spam_count + $4, \
			     updated_at = now()",
			uuid::Uuid::now_v7(),
			token,
			ham_inc,
			spam_inc,
		)
		.execute(&mut *tx)
		.await?;
	}
	tx.commit().await
}

/// The trained message totals.
pub async fn corpus(pool: &PgPool) -> Result<Corpus, sqlx::Error> {
	let row = sqlx::query!("SELECT ham_messages, spam_messages FROM bayes_corpus WHERE singleton")
		.fetch_one(pool)
		.await?;
	Ok(Corpus {
		ham_messages: row.ham_messages.max(0) as u64,
		spam_messages: row.spam_messages.max(0) as u64,
	})
}

/// Fetch counts for the given tokens in one query; absent tokens are omitted.
async fn counts_for(
	pool: &PgPool,
	tokens: &[String],
) -> Result<HashMap<String, TokenCounts>, sqlx::Error> {
	let rows = sqlx::query!(
		"SELECT token, ham_count, spam_count FROM bayes_token WHERE token = ANY($1)",
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

/// Score `text` as spam in `[0, 1]` using the trained corpus.
pub async fn score(pool: &PgPool, text: &str) -> Result<f64, sqlx::Error> {
	let tokens = bayes::tokenize(text);
	let corpus = corpus(pool).await?;
	let counts = counts_for(pool, &tokens).await?;
	Ok(bayes::classify(
		&tokens,
		|token| counts.get(token).copied().unwrap_or_default(),
		corpus,
	))
}
