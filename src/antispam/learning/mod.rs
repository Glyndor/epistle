//! What the user's own decisions teach the corpus of their account.
//!
//! A message moved into Junk, or out of it, or marked `$Junk` or
//! `$NotJunk`, is a verdict on that message. The corpus must hold each
//! verdict once: deciding the same thing twice changes nothing, and
//! deciding the other way takes back the lesson before adding the new one.
//! [`BayesStore::learn`](crate::antispam::corpus::BayesStore::learn) does that against a ledger of the messages the
//! account has learned (`bayes_learned`), keyed by a keyed hash of the text
//! read of the message (see [`scoring_text`](crate::antispam::scoring_text)):
//! the same reading the SMTP path scores and trains the shared corpus with, so
//! a message that is copied, moved or appended elsewhere is still the same
//! message, and an attachment is neither learned nor able to bury the words.
//!
//! The ledger and the token counts change in one transaction. When the
//! ledger cannot be written the counts do not move either, so a failure
//! never leaves a message trained without a record of it.
//!
//! The pieces:
//! - [`ledger`]: the transaction behind `BayesStore::learn`.
//! - [`stats`]: counters per account and the on/off switch.
//! - [`limiter`]: how much one account may teach per minute and per day.
//! - [`reset`]: dropping an account's corpus, with or without its switch.
//! - [`retry`]: running again a transaction PostgreSQL abandoned.

pub mod ledger;
pub mod limiter;
pub mod reset;
pub mod retry;
pub mod stats;
pub use stats::LearningStats;

/// Unique tokens kept from one message: the same cap the shared corpus
/// trains with ([`MAX_TRAIN_TOKENS`](crate::antispam::corpus::MAX_TRAIN_TOKENS)),
/// so a message costs the same rows whoever teaches it. The text is the one
/// [`scoring_text`](crate::antispam::scoring_text) reads, already cut to a
/// window; this bounds the rows a single lesson touches.
pub const MAX_LEARN_TOKENS: usize = crate::antispam::corpus::MAX_TRAIN_TOKENS;

/// Messages one account may hold in its ledger. At the limit the oldest
/// tenth is forgotten to make room: the corpus keeps what they taught, and
/// only the ability to take those lessons back is lost.
pub const MAX_LEARNED_PER_ACCOUNT: i64 = 100_000;

/// Token rows one account may hold in `bayes_token`, about 100 MB with their
/// index. A lesson that would add rows past it is refused, so what an account
/// can grow is bounded however many messages it sends.
pub const MAX_TOKEN_ROWS_PER_ACCOUNT: i64 = 250_000;

/// Tokens the lessons of one account may write in a day (the rows they touch,
/// new or not). A message of ordinary size is a few hundred tokens, so this
/// leaves thousands of lessons a day while a hostile one at the per-lesson
/// cap spends it in 200.
pub const MAX_TOKENS_PER_DAY: i64 = 1_000_000;

/// The ceilings [`BayesStore::learn`](crate::antispam::corpus::BayesStore::learn)
/// enforces. The defaults are the constants above; tests lower them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearnLimits {
	/// Unique tokens kept from one message.
	pub tokens_per_lesson: usize,
	/// Messages kept in the ledger of one account.
	pub ledger_entries: i64,
	/// Token rows one account may hold.
	pub token_rows: i64,
	/// Tokens one account may write in a day.
	pub tokens_per_day: i64,
}

impl Default for LearnLimits {
	fn default() -> Self {
		LearnLimits {
			tokens_per_lesson: MAX_LEARN_TOKENS,
			ledger_entries: MAX_LEARNED_PER_ACCOUNT,
			token_rows: MAX_TOKEN_ROWS_PER_ACCOUNT,
			tokens_per_day: MAX_TOKENS_PER_DAY,
		}
	}
}

/// What [`BayesStore::learn`] did with one verdict.
///
/// [`BayesStore::learn`]: crate::antispam::corpus::BayesStore::learn
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnOutcome {
	/// A message the account had not learned before was added.
	Learned,
	/// The account had learned the message the other way; that lesson was
	/// taken back and the new verdict added.
	Relearned,
	/// The account already held this verdict for the message; nothing moved.
	Repeated,
	/// Learning is switched off for the account; nothing moved.
	Disabled,
	/// The account holds as many token rows as it may; nothing moved.
	Refused,
	/// The account spent its day's tokens; nothing moved.
	Throttled,
	/// The scope cannot learn from a user (the shared one, or one being
	/// removed); nothing moved.
	Skipped,
	/// Nothing could be read of the message (see
	/// [`ScoringText::unread`](crate::antispam::scoring_text::ScoringText::unread)),
	/// so it has no words to count; nothing moved and nothing was spent.
	Unread,
	/// The database refused the lesson; nothing was recorded and nothing
	/// moved.
	Failed,
}

/// A verdict taught, and what it cost the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lesson {
	/// What was done with the verdict.
	pub outcome: LearnOutcome,
	/// The time the lesson kept the worker busy: reading the message and
	/// writing the corpus. The wait for the store's lock and for a pooled
	/// connection is not in it, because that time belongs to whoever held
	/// them and an account must not pay for it.
	pub busy: std::time::Duration,
}

impl From<LearnOutcome> for Lesson {
	fn from(outcome: LearnOutcome) -> Self {
		Lesson {
			outcome,
			busy: std::time::Duration::ZERO,
		}
	}
}

#[cfg(test)]
#[path = "learning_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "learning_tests_unread.rs"]
mod tests_unread;

#[cfg(test)]
#[path = "learning_tests_busy.rs"]
mod tests_busy;
