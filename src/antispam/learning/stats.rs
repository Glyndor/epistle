//! What each account's corpus has learned, and the switch that stops it.

use serde::Serialize;

use crate::antispam::corpus::{BayesStore, SHARED};

/// Accounts [`BayesStore::learning_stats_all`] returns at most.
pub const MAX_LISTED: i64 = 10_000;

/// The learning counters of one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LearningStats {
	/// The account name, which is the corpus scope.
	pub account: String,
	/// Whether the account's decisions teach its corpus.
	pub enabled: bool,
	/// Messages learned as spam, counting a message again when its verdict
	/// changed.
	pub spam_learned: i64,
	/// Messages learned as ham, counted the same way.
	pub ham_learned: i64,
	/// Earlier verdicts taken back because the user decided the other way.
	pub unlearned: i64,
	/// Decisions that repeated what the corpus already held.
	pub repeated: i64,
	/// Decisions refused because the account held as many token rows as it
	/// may.
	pub refused: i64,
	/// Decisions held back because the account spent its day's tokens.
	pub throttled: i64,
	/// Messages the ledger of the account holds.
	pub entries: i64,
	/// Token rows the account holds.
	pub token_rows: i64,
	/// Messages in the corpus that the ledger does not hold: taught before
	/// the ledger existed or by the server itself. They count again if the
	/// user moves them, and cannot be taken back.
	pub unrecorded: i64,
	/// Spam messages the corpus of the account holds, from any source.
	pub corpus_spam: i64,
	/// Ham messages the corpus of the account holds, from any source.
	pub corpus_ham: i64,
}

type Row = (
	String,
	bool,
	i64,
	i64,
	i64,
	i64,
	i64,
	i64,
	i64,
	i64,
	i64,
	i64,
);

impl From<Row> for LearningStats {
	fn from(row: Row) -> Self {
		let (corpus_spam, corpus_ham, entries) = (row.10, row.11, row.8);
		LearningStats {
			account: row.0,
			enabled: row.1,
			spam_learned: row.2,
			ham_learned: row.3,
			unlearned: row.4,
			repeated: row.5,
			refused: row.6,
			throttled: row.7,
			entries,
			token_rows: row.9,
			unrecorded: corpus_spam
				.saturating_add(corpus_ham)
				.saturating_sub(entries)
				.max(0),
			corpus_spam,
			corpus_ham,
		}
	}
}

/// The columns of a [`LearningStats`] row, joined to the corpus totals.
macro_rules! select {
	($tail:literal) => {
		concat!(
			"SELECT l.scope, l.enabled, l.spam_learned, l.ham_learned, l.unlearned, \
			 l.repeated, l.refused, l.throttled, l.entries, \
			 CASE WHEN l.token_rows < 0 THEN \
			 (SELECT COUNT(*) FROM bayes_token t WHERE t.scope = l.scope) \
			 ELSE l.token_rows END, \
			 COALESCE(c.spam_messages, 0), COALESCE(c.ham_messages, 0) \
			 FROM bayes_learning l LEFT JOIN bayes_corpus c ON c.scope = l.scope ",
			$tail
		)
	};
}

impl BayesStore {
	/// The counters of `account`; an account that never learned reads as
	/// learning on with every counter at zero.
	pub async fn learning_stats(&self, account: &str) -> Result<LearningStats, sqlx::Error> {
		let row: Option<Row> = sqlx::query_as(select!("WHERE l.scope = $1"))
			.bind(account)
			.fetch_optional(&self.pool)
			.await?;
		if let Some(row) = row {
			return Ok(row.into());
		}
		let token_rows: i64 =
			sqlx::query_scalar("SELECT COUNT(*) FROM bayes_token WHERE scope = $1")
				.bind(account)
				.fetch_one(&self.pool)
				.await?;
		let corpus = self.corpus(account).await?;
		let corpus_spam = i64::try_from(corpus.spam_messages).unwrap_or(i64::MAX);
		let corpus_ham = i64::try_from(corpus.ham_messages).unwrap_or(i64::MAX);
		Ok(LearningStats {
			account: account.to_string(),
			enabled: true,
			spam_learned: 0,
			ham_learned: 0,
			unlearned: 0,
			repeated: 0,
			refused: 0,
			throttled: 0,
			entries: 0,
			token_rows,
			unrecorded: corpus_spam.saturating_add(corpus_ham),
			corpus_spam,
			corpus_ham,
		})
	}

	/// The counters of every account that has a row, by name, at most
	/// [`MAX_LISTED`].
	pub async fn learning_stats_all(&self) -> Result<Vec<LearningStats>, sqlx::Error> {
		let rows: Vec<Row> = sqlx::query_as(select!("ORDER BY l.scope LIMIT $1"))
			.bind(MAX_LISTED)
			.fetch_all(&self.pool)
			.await?;
		Ok(rows.into_iter().map(Into::into).collect())
	}

	/// Switch learning on or off for `account`. Returns whether the setting
	/// changed. The shared scope has no switch.
	pub async fn set_learning(&self, account: &str, enabled: bool) -> Result<bool, sqlx::Error> {
		if account == SHARED {
			return Ok(false);
		}
		let mut tx = self.pool.begin().await?;
		// A new row does not know how many token rows the account holds (-1);
		// the first lesson counts them (see `ledger`).
		sqlx::query(
			"INSERT INTO bayes_learning (scope, token_rows) VALUES ($1, -1) \
			 ON CONFLICT (scope) DO NOTHING",
		)
		.bind(account)
		.execute(&mut *tx)
		.await?;
		let before: bool =
			sqlx::query_scalar("SELECT enabled FROM bayes_learning WHERE scope = $1 FOR UPDATE")
				.bind(account)
				.fetch_one(&mut *tx)
				.await?;
		sqlx::query("UPDATE bayes_learning SET enabled = $2, updated_at = now() WHERE scope = $1")
			.bind(account)
			.bind(enabled)
			.execute(&mut *tx)
			.await?;
		tx.commit().await?;
		Ok(before != enabled)
	}
}
