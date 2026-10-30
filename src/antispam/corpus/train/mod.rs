//! The write path of the corpus: [`BayesStore::train`].
//!
//! A child module of `corpus`, so it reaches the store's private fields.

use std::borrow::Cow;

use super::{BayesStore, MAX_TRAIN_TOKENS};
use crate::antispam::bayes;
use crate::antispam::training_queue::{MAX_TRAINING_BYTES, seam_after, seam_before};

/// The window of `text` a message is trained on or scored on: all of it when
/// it fits in [`MAX_TRAINING_BYTES`], else its first and its last half joined
/// by a newline, each cut on a character boundary (see
/// [`crate::antispam::training_queue::training_window`] for the bytes).
pub(super) fn training_window(text: &str) -> Cow<'_, str> {
	if text.len() <= MAX_TRAINING_BYTES {
		return Cow::Borrowed(text);
	}
	let bytes = text.as_bytes();
	let mut head = seam_before(bytes, MAX_TRAINING_BYTES / 2);
	while !text.is_char_boundary(head) {
		head -= 1;
	}
	let mut tail = seam_after(
		bytes,
		bytes.len() - (MAX_TRAINING_BYTES - MAX_TRAINING_BYTES / 2 - 1),
	);
	while !text.is_char_boundary(tail) {
		tail += 1;
	}
	let mut window = String::with_capacity(MAX_TRAINING_BYTES);
	window.push_str(&text[..head]);
	window.push('\n');
	window.push_str(&text[tail..]);
	Cow::Owned(window)
}

/// The tokens a message is trained or scored on.
pub(super) struct WindowTokens {
	/// The distinct tokens, lowercased.
	pub(super) plain: Vec<String>,
	/// The window held more distinct tokens than the cap, so these are a
	/// keyed sample of them and the message is not an ordinary one.
	pub(super) capped: bool,
}

impl BayesStore {
	/// The distinct tokens of the window of `text`, at most `cap`. A message
	/// that fits keeps all of its tokens in order of appearance, as it always
	/// did. One with more is cut down: the first and the last `positional`
	/// distinct tokens are kept, where a message says what it is, and the rest
	/// of the room goes to the tokens whose keyed hash is smallest, so the
	/// sender, who does not hold the key, cannot choose which of the others
	/// are read by where it puts them. The scan keeps `cap` entries at most.
	pub(super) fn window_tokens(&self, text: &str, cap: usize, positional: usize) -> WindowTokens {
		let window = training_window(text);
		let clipped = matches!(window, Cow::Owned(_));
		let first = bayes::tokenize_bounded(&window, cap + 1);
		if first.len() <= cap {
			return WindowTokens {
				plain: first,
				capped: clipped,
			};
		}
		let mut plain: Vec<String> = first.into_iter().take(positional).collect();
		for token in bayes::last_tokens(&window, positional) {
			if !plain.contains(&token) {
				plain.push(token);
			}
		}
		let kept: std::collections::HashSet<String> = plain.iter().cloned().collect();
		plain.extend(bayes::sample_tokens_without(
			&window,
			cap - plain.len(),
			|token| self.tag(token),
			&kept,
		));
		WindowTokens {
			plain,
			capped: true,
		}
	}

	/// The hashed tokens one message adds: [`BayesStore::window_tokens`]
	/// hashed and sorted. The order is the one the rows are written in, the
	/// same for every transaction, so concurrent trainings cannot lock rows
	/// crosswise.
	fn training_tokens(&self, text: &str) -> Vec<String> {
		self.lesson_tokens(text, MAX_TRAIN_TOKENS)
	}

	/// [`BayesStore::training_tokens`] with room for `cap` tokens. A user's
	/// lesson reads and cuts a message exactly as the shared corpus does and
	/// differs only in the cap it may be lowered to.
	pub(in crate::antispam) fn lesson_tokens(&self, text: &str, cap: usize) -> Vec<String> {
		let mut hashed: Vec<String> = self
			.window_tokens(text, cap, 0)
			.plain
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
mod tests;
