//! Dropping what an account's corpus holds.
//!
//! Two operations share one transaction body ([`purge`]) and differ in what
//! they leave behind:
//!
//! - [`BayesStore::reset_learning`] is the operator's `learning reset`: the
//!   corpus, the record and the counters go, and the on/off switch stays, so
//!   the account that was switched off to stop it teaching is still off.
//! - `BayesStore::forget_scope` is account removal: everything goes, the
//!   switch included, so a recreated account starts clean.

use sqlx::{Postgres, Transaction};

use super::retry::retrying;
use crate::antispam::corpus::{BayesStore, SHARED};

/// What [`purge`] leaves of the row of `bayes_learning`.
#[derive(Clone, Copy)]
pub(crate) enum Keep {
	/// Zero the counters and keep `enabled`.
	Switch,
	/// Delete the row.
	Nothing,
}

/// Drop the record, the message totals and the tokens of `scope`, taking the
/// locks in the order every path takes them (see [`super::ledger`]): the row
/// of `bayes_learning` first, then `bayes_learned`, `bayes_corpus` and
/// `bayes_token`. Returns the token rows dropped.
pub(crate) async fn purge(
	tx: &mut Transaction<'_, Postgres>,
	scope: &str,
	keep: Keep,
) -> Result<u64, sqlx::Error> {
	let first = match keep {
		Keep::Nothing => "DELETE FROM bayes_learning WHERE scope = $1",
		Keep::Switch => {
			"UPDATE bayes_learning SET spam_learned = 0, ham_learned = 0, unlearned = 0, \
			 repeated = 0, refused = 0, entries = 0, updated_at = now() WHERE scope = $1"
		}
	};
	sqlx::query(first).bind(scope).execute(&mut **tx).await?;
	sqlx::query("DELETE FROM bayes_learned WHERE scope = $1")
		.bind(scope)
		.execute(&mut **tx)
		.await?;
	sqlx::query("DELETE FROM bayes_corpus WHERE scope = $1")
		.bind(scope)
		.execute(&mut **tx)
		.await?;
	let tokens = sqlx::query("DELETE FROM bayes_token WHERE scope = $1")
		.bind(scope)
		.execute(&mut **tx)
		.await?
		.rows_affected();
	Ok(tokens)
}

impl BayesStore {
	/// Drop the corpus and the record of `scope` and zero its counters,
	/// keeping the on/off switch. Returns the token rows dropped. The shared
	/// corpus cannot be reset here.
	pub async fn reset_learning(&self, scope: &str) -> Result<u64, sqlx::Error> {
		if scope == SHARED {
			return Ok(0);
		}
		let _scope_guard = self.scope_lock.lock().await;
		retrying(|| async {
			let mut tx = self.pool.begin().await?;
			let tokens = purge(&mut tx, scope, Keep::Switch).await?;
			tx.commit().await?;
			Ok(tokens)
		})
		.await
	}

	/// Drop everything of `scope` for good, in one transaction. The caller
	/// holds the scope lock and has tombstoned the scope.
	pub(crate) async fn purge_scope(&self, scope: &str) -> Result<u64, sqlx::Error> {
		retrying(|| async {
			let mut tx = self.pool.begin().await?;
			let tokens = purge(&mut tx, scope, Keep::Nothing).await?;
			tx.commit().await?;
			Ok(tokens)
		})
		.await
	}
}
