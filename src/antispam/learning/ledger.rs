//! The transaction that teaches one verdict, once.
//!
//! # Lock order
//!
//! Every path that writes the corpus of an account takes its locks in this
//! order, so two of them can wait for each other but never wait in a circle:
//!
//! 1. the row of the account in `bayes_learning`;
//! 2. the rows of `bayes_learned`;
//! 3. the row of the account in `bayes_corpus`;
//! 4. the rows of `bayes_token`.
//!
//! [`BayesStore::learn`] and the reset and removal in [`super::reset`] follow
//! it. `BayesStore::train`, which teaches the shared corpus from the SMTP
//! path, takes `bayes_corpus` and then `bayes_token`, a suffix of the same
//! order, and shares the in-process `scope_lock` with them. A transaction that
//! PostgreSQL abandons anyway is run again ([`super::retry`]).

use sqlx::{Postgres, Transaction};

use super::retry::retrying;
use super::{LearnOutcome, MAX_LEARN_TOKENS, MAX_LEARNED_PER_ACCOUNT};
use crate::antispam::bayes;
use crate::antispam::corpus::{BayesStore, SHARED};
use crate::antispam::training_queue::MAX_TRAINING_BYTES;

impl BayesStore {
	/// The keyed hash that names a message in the ledger: the window of the
	/// message under the instance key, hex encoded. It is not a token hash,
	/// so the two never share a space.
	fn message_digest(&self, window: &[u8]) -> String {
		let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.key);
		let mut context = ring::hmac::Context::with_key(&key);
		context.update(b"learned-message\0");
		context.update(window);
		context
			.sign()
			.as_ref()
			.iter()
			.fold(String::new(), |mut acc, byte| {
				use std::fmt::Write;
				let _ = write!(acc, "{byte:02x}");
				acc
			})
	}

	/// Teach the corpus of `scope` that the message whose window is `window`
	/// is spam (`spam`) or ham, once.
	///
	/// - A message the account has not learned is added.
	/// - The same verdict again changes nothing.
	/// - The other verdict takes back the earlier lesson, token by token,
	///   and adds the new one.
	///
	/// The ledger row, the token counts, the message totals and the
	/// counters change in one transaction. An error leaves all of them as
	/// they were, so nothing is trained without being recorded. The shared
	/// scope never learns from a user.
	pub async fn learn(
		&self,
		scope: &str,
		window: &[u8],
		spam: bool,
	) -> Result<LearnOutcome, sqlx::Error> {
		if scope == SHARED {
			return Ok(LearnOutcome::Skipped);
		}
		let _scope_guard = self.scope_lock.lock().await;
		if self
			.tombstones
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.contains(scope)
		{
			return Ok(LearnOutcome::Skipped);
		}
		// The caller already trimmed the window; this bound holds for any
		// caller, and comes before tokenizing so the work is linear in it.
		let window = &window[..window.len().min(MAX_TRAINING_BYTES)];
		let text = String::from_utf8_lossy(window);
		let tokens: Vec<String> = bayes::tokenize(&text)
			.iter()
			.take(MAX_LEARN_TOKENS)
			.map(|token| self.hash(token))
			.collect();
		let digest = self.message_digest(window);
		retrying(|| self.learn_once(scope, &tokens, &digest, spam)).await
	}

	/// One attempt of [`BayesStore::learn`].
	async fn learn_once(
		&self,
		scope: &str,
		tokens: &[String],
		digest: &str,
		spam: bool,
	) -> Result<LearnOutcome, sqlx::Error> {
		let mut tx = self.pool.begin().await?;
		sqlx::query(
			"INSERT INTO bayes_learning (scope) VALUES ($1) ON CONFLICT (scope) DO NOTHING",
		)
		.bind(scope)
		.execute(&mut *tx)
		.await?;
		// The row lock serializes every lesson of the account, in this
		// process and in any other.
		let Some((enabled, entries)) = sqlx::query_as::<_, (bool, i64)>(
			"SELECT enabled, entries FROM bayes_learning WHERE scope = $1 FOR UPDATE",
		)
		.bind(scope)
		.fetch_optional(&mut *tx)
		.await?
		else {
			// The account was removed between the two statements.
			tx.rollback().await?;
			return Ok(LearnOutcome::Skipped);
		};
		if !enabled {
			tx.rollback().await?;
			return Ok(LearnOutcome::Disabled);
		}
		let held: Option<(bool, i32)> = sqlx::query_as(
			"SELECT spam, tokens FROM bayes_learned WHERE scope = $1 AND digest = $2",
		)
		.bind(scope)
		.bind(digest)
		.fetch_optional(&mut *tx)
		.await?;
		let outcome = match held {
			Some((held, _)) if held == spam => {
				bump(&mut tx, scope, Counter::Repeated).await?;
				LearnOutcome::Repeated
			}
			Some((_, counted)) => {
				// Only the tokens that were counted are moved back.
				let counted = usize::try_from(counted).unwrap_or(0).min(tokens.len());
				let (ham, spam_delta) = if spam { (-1, 1) } else { (1, -1) };
				adjust(&mut tx, scope, &tokens[..counted], ham, spam_delta).await?;
				sqlx::query(
					"UPDATE bayes_learned SET spam = $3, learned_at = now() WHERE scope = $1 AND digest = $2",
				)
				.bind(scope)
				.bind(digest)
				.bind(spam)
				.execute(&mut *tx)
				.await?;
				bump(&mut tx, scope, Counter::Relearned { spam }).await?;
				LearnOutcome::Relearned
			}
			None if entries >= MAX_LEARNED_PER_ACCOUNT => {
				bump(&mut tx, scope, Counter::Refused).await?;
				LearnOutcome::Refused
			}
			None => {
				sqlx::query(
					"INSERT INTO bayes_learned (scope, digest, spam, tokens) VALUES ($1, $2, $3, $4)",
				)
				.bind(scope)
				.bind(digest)
				.bind(spam)
				.bind(i32::try_from(tokens.len()).unwrap_or(i32::MAX))
				.execute(&mut *tx)
				.await?;
				let (ham, spam_delta) = if spam { (0, 1) } else { (1, 0) };
				adjust(&mut tx, scope, tokens, ham, spam_delta).await?;
				bump(&mut tx, scope, Counter::Learned { spam }).await?;
				LearnOutcome::Learned
			}
		};
		tx.commit().await?;
		Ok(outcome)
	}
}

/// The counters one lesson moves.
#[derive(Clone, Copy)]
enum Counter {
	/// A decision that repeated what the ledger held.
	Repeated,
	/// A decision refused because the ledger was full.
	Refused,
	/// A message new to the ledger, on the given side.
	Learned { spam: bool },
	/// A verdict taken back, and the new one on the given side.
	Relearned { spam: bool },
}

/// Add one to the counters `counter` names on the row of `scope`.
async fn bump(
	tx: &mut Transaction<'_, Postgres>,
	scope: &str,
	counter: Counter,
) -> Result<(), sqlx::Error> {
	let sql = match counter {
		Counter::Repeated => {
			"UPDATE bayes_learning SET repeated = repeated + 1, updated_at = now() WHERE scope = $1"
		}
		Counter::Refused => {
			"UPDATE bayes_learning SET refused = refused + 1, updated_at = now() WHERE scope = $1"
		}
		Counter::Learned { spam: true } => {
			"UPDATE bayes_learning SET spam_learned = spam_learned + 1, entries = entries + 1, \
			 updated_at = now() WHERE scope = $1"
		}
		Counter::Learned { spam: false } => {
			"UPDATE bayes_learning SET ham_learned = ham_learned + 1, entries = entries + 1, \
			 updated_at = now() WHERE scope = $1"
		}
		Counter::Relearned { spam: true } => {
			"UPDATE bayes_learning SET spam_learned = spam_learned + 1, unlearned = unlearned + 1, \
			 updated_at = now() WHERE scope = $1"
		}
		Counter::Relearned { spam: false } => {
			"UPDATE bayes_learning SET ham_learned = ham_learned + 1, unlearned = unlearned + 1, \
			 updated_at = now() WHERE scope = $1"
		}
	};
	sqlx::query(sql).bind(scope).execute(&mut **tx).await?;
	Ok(())
}

/// Move the message totals and the counts of `tokens` by `ham` and `spam`
/// (negative to take a lesson back, never below zero), in two statements
/// whatever the number of tokens.
async fn adjust(
	tx: &mut Transaction<'_, Postgres>,
	scope: &str,
	tokens: &[String],
	ham: i64,
	spam: i64,
) -> Result<(), sqlx::Error> {
	sqlx::query(
		"INSERT INTO bayes_corpus (scope, ham_messages, spam_messages) \
		 VALUES ($1, GREATEST($2::bigint, 0), GREATEST($3::bigint, 0)) \
		 ON CONFLICT (scope) DO UPDATE SET \
		     ham_messages = GREATEST(bayes_corpus.ham_messages + $2::bigint, 0), \
		     spam_messages = GREATEST(bayes_corpus.spam_messages + $3::bigint, 0), \
		     updated_at = now()",
	)
	.bind(scope)
	.bind(ham)
	.bind(spam)
	.execute(&mut **tx)
	.await?;
	if tokens.is_empty() {
		return Ok(());
	}
	let ids: Vec<uuid::Uuid> = tokens.iter().map(|_| uuid::Uuid::now_v7()).collect();
	sqlx::query(
		"INSERT INTO bayes_token (id, scope, token, ham_count, spam_count) \
		 SELECT t.id, $2, t.token, GREATEST($3::bigint, 0), GREATEST($4::bigint, 0) \
		 FROM UNNEST($1::uuid[], $5::text[]) AS t(id, token) \
		 ON CONFLICT (scope, token) DO UPDATE SET \
		     ham_count = GREATEST(bayes_token.ham_count + $3::bigint, 0), \
		     spam_count = GREATEST(bayes_token.spam_count + $4::bigint, 0), \
		     updated_at = now()",
	)
	.bind(ids)
	.bind(scope)
	.bind(ham)
	.bind(spam)
	.bind(tokens)
	.execute(&mut **tx)
	.await?;
	Ok(())
}
