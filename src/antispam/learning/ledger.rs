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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sqlx::{Connection, Postgres, Transaction};

use super::retry::retrying;
use super::{LearnOutcome, Lesson};
use crate::antispam::corpus::{BayesStore, SHARED};
use crate::antispam::scoring_text::scoring_text;

impl BayesStore {
	/// The keyed hash that names a message in the ledger: the text read of
	/// the message under the instance key, hex encoded. It is not a token
	/// hash, so the two never share a space.
	fn message_digest(&self, text: &str) -> String {
		let mut context = ring::hmac::Context::with_key(&self.mac);
		context.update(b"learned-message\0");
		context.update(text.as_bytes());
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

	/// Teach the corpus of `scope` that the raw message `raw` is spam
	/// (`spam`) or ham, once.
	///
	/// The message is reduced first to the text a person reads of it, as the
	/// SMTP path does (see [`scoring_text`]): headers and text parts, cut to a
	/// window, at most [`LearnLimits::tokens_per_lesson`](super::LearnLimits)
	/// distinct tokens. A message that cannot be read is
	/// [`LearnOutcome::Unread`] and costs nothing but the reading.
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
		raw: &[u8],
		spam: bool,
	) -> Result<LearnOutcome, sqlx::Error> {
		Ok(self.learn_timed(scope, raw, spam).await?.outcome)
	}

	/// [`BayesStore::learn`], also saying how long it kept the worker busy
	/// ([`Lesson::busy`]): the reduction and the transaction, not the wait for
	/// the lock of the store or for a connection.
	pub async fn learn_timed(
		&self,
		scope: &str,
		raw: &[u8],
		spam: bool,
	) -> Result<Lesson, sqlx::Error> {
		if scope == SHARED {
			return Ok(LearnOutcome::Skipped.into());
		}
		// Read and hashed before anything is locked, so the work that grows
		// with the message never holds the lock.
		let started = Instant::now();
		let reduced = scoring_text(raw);
		if reduced.unread {
			tracing::warn!("a message that could not be read was not learned from");
			return Ok(Lesson {
				outcome: LearnOutcome::Unread,
				busy: started.elapsed(),
			});
		}
		let tokens = self.lesson_tokens(&reduced.text, self.limits.tokens_per_lesson);
		let digest = self.message_digest(&reduced.text);
		let prepared = started.elapsed();
		let _scope_guard = self.scope_lock.lock().await;
		if self
			.tombstones
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.contains(scope)
		{
			return Ok(Lesson {
				outcome: LearnOutcome::Skipped,
				busy: prepared,
			});
		}
		let writing = AtomicU64::new(0);
		let outcome = retrying(|| async {
			let (outcome, took) = self
				.learn_once(scope, &reduced.text, &tokens, &digest, spam)
				.await?;
			writing.fetch_add(
				u64::try_from(took.as_nanos()).unwrap_or(u64::MAX),
				Ordering::Relaxed,
			);
			Ok(outcome)
		})
		.await?;
		Ok(Lesson {
			outcome,
			busy: prepared.saturating_add(Duration::from_nanos(writing.load(Ordering::Relaxed))),
		})
	}

	/// One attempt of [`BayesStore::learn`].
	async fn learn_once(
		&self,
		scope: &str,
		text: &str,
		tokens: &[String],
		digest: &str,
		spam: bool,
	) -> Result<(LearnOutcome, Duration), sqlx::Error> {
		let limits = self.limits;
		// The wait for a pooled connection is not the lesson's own time.
		let mut connection = self.pool.acquire().await?;
		let began = Instant::now();
		let mut tx = connection.begin().await?;
		// A row that starts here does not know how many token rows the account
		// holds (-1), because it may have learned before the record existed.
		// It is counted below, once the row is locked, and not here: a count
		// taken while another transaction removes the account would be of
		// rows that are about to go.
		sqlx::query(
			"INSERT INTO bayes_learning (scope, token_rows) VALUES ($1, -1) \
			 ON CONFLICT (scope) DO NOTHING",
		)
		.bind(scope)
		.execute(&mut *tx)
		.await?;
		// The row lock serializes every lesson of the account, in this
		// process and in any other.
		let Some((enabled, entries, token_rows, spent)) =
			sqlx::query_as::<_, (bool, i64, i64, i64)>(
				"SELECT enabled, entries, token_rows, \
				 CASE WHEN budget_day = CURRENT_DATE THEN budget_tokens ELSE 0 END \
				 FROM bayes_learning WHERE scope = $1 FOR UPDATE",
			)
			.bind(scope)
			.fetch_optional(&mut *tx)
			.await?
		else {
			// The account was removed between the two statements.
			tx.rollback().await?;
			return Ok((LearnOutcome::Skipped, began.elapsed()));
		};
		if !enabled {
			tx.rollback().await?;
			return Ok((LearnOutcome::Disabled, began.elapsed()));
		}
		let token_rows = if token_rows < 0 {
			sqlx::query_scalar(
				"UPDATE bayes_learning SET token_rows = \
				 (SELECT COUNT(*) FROM bayes_token WHERE scope = $1) \
				 WHERE scope = $1 RETURNING token_rows",
			)
			.bind(scope)
			.fetch_one(&mut *tx)
			.await?
		} else {
			token_rows
		};
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
				// Only the tokens that were counted are moved back. A cap that
				// changed since gives another set, so the set of that cap is
				// read again from the same text.
				let counted = usize::try_from(counted).unwrap_or(0);
				let back = if counted == tokens.len() {
					tokens.to_vec()
				} else {
					self.lesson_tokens(text, counted)
				};
				let counted = back.len();
				if over_budget(spent, counted, &limits) {
					bump(&mut tx, scope, Counter::Throttled).await?;
					LearnOutcome::Throttled
				} else {
					let (ham, spam_delta) = if spam { (-1, 1) } else { (1, -1) };
					adjust(&mut tx, scope, &back, ham, spam_delta).await?;
					sqlx::query(
						"UPDATE bayes_learned SET spam = $3, learned_at = now() WHERE scope = $1 AND digest = $2",
					)
					.bind(scope)
					.bind(digest)
					.bind(spam)
					.execute(&mut *tx)
					.await?;
					spend(&mut tx, scope, 0, counted).await?;
					bump(&mut tx, scope, Counter::Relearned { spam }).await?;
					LearnOutcome::Relearned
				}
			}
			None if over_budget(spent, tokens.len(), &limits) => {
				bump(&mut tx, scope, Counter::Throttled).await?;
				LearnOutcome::Throttled
			}
			None => {
				let existing: i64 = sqlx::query_scalar(
					"SELECT COUNT(*) FROM bayes_token WHERE scope = $1 AND token = ANY($2)",
				)
				.bind(scope)
				.bind(tokens)
				.fetch_one(&mut *tx)
				.await?;
				let new_rows = i64::try_from(tokens.len()).unwrap_or(i64::MAX) - existing;
				if new_rows > 0 && token_rows.saturating_add(new_rows) > limits.token_rows {
					bump(&mut tx, scope, Counter::Refused).await?;
					LearnOutcome::Refused
				} else {
					if entries >= limits.ledger_entries {
						make_room(&mut tx, scope, limits.ledger_entries).await?;
					}
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
					spend(&mut tx, scope, new_rows, tokens.len()).await?;
					bump(&mut tx, scope, Counter::Learned { spam }).await?;
					LearnOutcome::Learned
				}
			}
		};
		tx.commit().await?;
		Ok((outcome, began.elapsed()))
	}
}

/// Whether `cost` more tokens would take the account past its day's budget.
fn over_budget(spent: i64, cost: usize, limits: &super::LearnLimits) -> bool {
	spent.saturating_add(i64::try_from(cost).unwrap_or(i64::MAX)) > limits.tokens_per_day
}

/// Forget the oldest tenth of the account's ledger (at least one message) to
/// make room for a new one. The corpus keeps what those messages taught.
async fn make_room(
	tx: &mut Transaction<'_, Postgres>,
	scope: &str,
	ledger_entries: i64,
) -> Result<(), sqlx::Error> {
	let batch = (ledger_entries / 10).max(1);
	let forgotten = sqlx::query(
		"DELETE FROM bayes_learned WHERE scope = $1 AND digest IN \
		 (SELECT digest FROM bayes_learned WHERE scope = $1 ORDER BY learned_at LIMIT $2)",
	)
	.bind(scope)
	.bind(batch)
	.execute(&mut **tx)
	.await?
	.rows_affected();
	sqlx::query("UPDATE bayes_learning SET entries = GREATEST(entries - $2, 0) WHERE scope = $1")
		.bind(scope)
		.bind(i64::try_from(forgotten).unwrap_or(i64::MAX))
		.execute(&mut **tx)
		.await?;
	Ok(())
}

/// Record `new_rows` token rows and `cost` tokens written on today's budget.
async fn spend(
	tx: &mut Transaction<'_, Postgres>,
	scope: &str,
	new_rows: i64,
	cost: usize,
) -> Result<(), sqlx::Error> {
	sqlx::query(
		"UPDATE bayes_learning SET token_rows = token_rows + $2, budget_day = CURRENT_DATE, \
		 budget_tokens = CASE WHEN budget_day = CURRENT_DATE THEN budget_tokens + $3 ELSE $3 END, \
		 updated_at = now() WHERE scope = $1",
	)
	.bind(scope)
	.bind(new_rows)
	.bind(i64::try_from(cost).unwrap_or(i64::MAX))
	.execute(&mut **tx)
	.await?;
	Ok(())
}

/// The counters one lesson moves.
#[derive(Clone, Copy)]
enum Counter {
	/// A decision that repeated what the ledger held.
	Repeated,
	/// A decision refused because the account held as many token rows as it may.
	Refused,
	/// A decision held back because the account spent its day's tokens.
	Throttled,
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
		Counter::Throttled => {
			"UPDATE bayes_learning SET throttled = throttled + 1, updated_at = now() WHERE scope = $1"
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
