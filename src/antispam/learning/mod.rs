//! What the user's own decisions teach the corpus of their account.
//!
//! A message moved into Junk, or out of it, or marked `$Junk` or
//! `$NotJunk`, is a verdict on that message. The corpus must hold each
//! verdict once: deciding the same thing twice changes nothing, and
//! deciding the other way takes back the lesson before adding the new one.
//! [`BayesStore::learn`](crate::antispam::corpus::BayesStore::learn) does that against a ledger of the messages the
//! account has learned (`bayes_learned`), keyed by a keyed hash of the
//! message window so a message that is copied, moved or appended elsewhere
//! is still the same message.
//!
//! The ledger and the token counts change in one transaction. When the
//! ledger cannot be written the counts do not move either, so a failure
//! never leaves a message trained without a record of it.
//!
//! The pieces:
//! - [`ledger`]: the transaction behind `BayesStore::learn`.
//! - [`stats`]: counters per account and the on/off switch.
//! - [`limiter`]: how much one account may teach per minute and per day.

pub mod ledger;
pub mod limiter;
pub mod stats;

pub use ledger::forget_learning;
pub use stats::LearningStats;

/// Unique tokens kept from one message. The window is already bounded in
/// bytes; this bounds the rows a single lesson touches, so a window made
/// of short distinct words costs the same as an ordinary message.
pub const MAX_LEARN_TOKENS: usize = 5_000;

/// Messages one account may hold in its ledger. At the limit the account
/// keeps its corpus and learns nothing new until the operator resets it.
pub const MAX_LEARNED_PER_ACCOUNT: i64 = 100_000;

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
	/// The ledger of the account is full; nothing moved.
	Refused,
	/// The scope cannot learn from a user (the shared one, or one being
	/// removed); nothing moved.
	Skipped,
	/// The database refused the lesson; nothing was recorded and nothing
	/// moved.
	Failed,
}

#[cfg(test)]
#[path = "learning_tests.rs"]
mod tests;
