//! The write path of the corpus: [`BayesStore::train`].
//!
//! A child module of `corpus`, so it reaches the store's private fields.

use super::{BayesStore, MAX_TRAIN_TOKENS};
use crate::antispam::bayes;
use crate::antispam::training_queue::MAX_TRAINING_BYTES;

/// The leading window of `text` a message is trained on: at most
/// [`MAX_TRAINING_BYTES`], cut on a character boundary.
fn training_window(text: &str) -> &str {
	let mut end = text.len().min(MAX_TRAINING_BYTES);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	&text[..end]
}

impl BayesStore {
	/// The hashed tokens one message adds: the distinct tokens of its
	/// window, at most [`MAX_TRAIN_TOKENS`], sorted. The scan stops at the
	/// cap, so the work and the memory do not grow with the message. The
	/// order is the one the rows are written in, the same for every
	/// transaction, so concurrent trainings cannot lock rows crosswise.
	fn training_tokens(&self, text: &str) -> Vec<String> {
		let window = training_window(text);
		let mut hashed: Vec<String> = bayes::tokenize_bounded(window, MAX_TRAIN_TOKENS)
			.iter()
			.map(|token| self.hash(token))
			.collect();
		hashed.sort_unstable();
		hashed.dedup();
		hashed
	}

	/// Train the `scope` corpus on one message: bump the message total and each
	/// token's ham or spam count, atomically, in a bounded amount of work (see
	/// the module doc of `corpus`): a window of the text, at most
	/// [`MAX_TRAIN_TOKENS`] distinct tokens, and one statement for all of them.
	pub async fn train(&self, scope: &str, text: &str, spam: bool) -> Result<(), sqlx::Error> {
		// Tokenised and hashed before anything is locked, so the work that
		// grows with the message never holds the lock.
		let tokens = self.training_tokens(text);
		// Hold the per-store lock across the SQL so a worker that just passed
		// the tombstone check cannot race the DELETE a concurrent
		// `forget_scope` is committing. The lock is per-instance and does not
		// span processes.
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
		let ham_inc: i64 = if spam { 0 } else { 1 };
		let spam_inc: i64 = if spam { 1 } else { 0 };
		let ids: Vec<uuid::Uuid> = tokens.iter().map(|_| uuid::Uuid::now_v7()).collect();
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

		if !tokens.is_empty() {
			sqlx::query(
				"INSERT INTO bayes_token (id, scope, token, ham_count, spam_count) \
				 SELECT batch.id, $1::text, batch.token, $2::bigint, $3::bigint \
				 FROM UNNEST($4::uuid[], $5::text[]) AS batch(id, token) \
				 ON CONFLICT (scope, token) DO UPDATE SET \
				     ham_count = bayes_token.ham_count + $2, \
				     spam_count = bayes_token.spam_count + $3, \
				     updated_at = now()",
			)
			.bind(scope)
			.bind(ham_inc)
			.bind(spam_inc)
			.bind(&ids)
			.bind(&tokens)
			.execute(&mut *tx)
			.await?;
		}
		tx.commit().await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_window_never_cuts_a_character_in_half() {
		// A 4-byte character straddling the limit.
		let mut text = "a".repeat(MAX_TRAINING_BYTES - 2);
		text.push('\u{1F600}');
		text.push_str("tail");
		let window = training_window(&text);
		assert_eq!(window.len(), MAX_TRAINING_BYTES - 2);
		assert!(!window.contains("tail"));
	}

	#[test]
	fn a_short_text_is_kept_whole() {
		assert_eq!(training_window("short text"), "short text");
		assert_eq!(training_window(""), "");
	}
}
