//! Trained Bayesian corpus stored in PostgreSQL.
//!
//! Holds the per-token ham/spam counts and message totals that the pure
//! classifier in [`super::bayes`] consumes. Training updates the counts;
//! scoring reads them and delegates the math to `bayes::classify`.
//!
//! Every operation is keyed by a `scope`: a per-account corpus, or the shared
//! corpus [`SHARED`] (`""`) the server trains from its own accept/reject
//! decisions. Scopes are isolated: training one account never affects another.
//!
//! **Encryption at rest:** tokens are never stored in clear. Each token is
//! replaced by a keyed HMAC-SHA256 of its text under a per-instance key held in
//! a `0600` file outside the database, so a database compromise reveals neither
//! the words users received nor what they marked as spam, only opaque,
//! per-instance hashes. The hash is deterministic, so lookups still work, and
//! token identity (all the classifier needs) is preserved.
//!
//! **Bounded work.** Training is fed by mail any remote sender can send, so one
//! message costs a fixed amount whatever its size: [`BayesStore::train`] reads
//! a window of [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES) of the text, keeps at most
//! [`MAX_TRAIN_TOKENS`] distinct tokens and writes them in one statement. The
//! SMTP path does not call it directly: [`BayesStore::submit_training`] queues
//! the job for a small, fixed set of workers (see [`super::shared_training`]).
//!
//! **Lock order.** Every transaction that takes more than one of these locks
//! takes them in this order, so two of them cannot wait for each other (a
//! process-local `scope_lock` first, then rows in the database):
//! `scope_lock`, then `bayes_corpus`, then `bayes_token`. Whatever must be
//! locked before the totals (a per-account ledger of lessons, for instance)
//! comes before `bayes_corpus`. Inside `bayes_token` the rows are written in
//! ascending token order. [`BayesStore::forget_scope`] follows the same order.

mod score;
mod store;
mod train;
mod training;

#[cfg(test)]
use crate::antispam::bayes::Corpus;
#[cfg(test)]
use crate::storage::load_or_create_key_file;
pub use score::{BayesScorer, scoring_scope};
pub use store::{BayesStore, TombstoneSet, new_tombstone_set};
#[cfg(test)]
use store::{KEY_FILE, hash_token};

/// The shared corpus scope (the server's own accept/reject learning).
pub const SHARED: &str = "";

/// The most distinct tokens one message adds to a corpus. Also the cap a
/// user's junk lesson is held to; a message with more distinct words than
/// this has told the corpus all it will learn from the words it opens with.
pub const MAX_TRAIN_TOKENS: usize = 5000;

/// The most distinct tokens one message is scored on, from the same window of
/// its text as training. The classifier keeps the few most telling tokens, so
/// a message under this and the window scores exactly as it always did; scoring
/// runs inline in the session of an unauthenticated sender, so a larger one
/// cannot cost more.
pub const MAX_SCORE_TOKENS: usize = 5000;

/// Of those, the first and the last this many distinct tokens of the window
/// are always read when there are more than the cap: where a message says what
/// it is. The rest are chosen by a keyed hash.
pub const SCORE_POSITIONAL: usize = 1000;

/// The lowest score a message gets when it holds more distinct tokens than
/// [`MAX_SCORE_TOKENS`]: neither clean nor spam. Such a message is scored on a
/// sample of its words, which is what someone who wants to hide spam in a
/// pile of filler hopes for, so it never counts as a message the corpus is
/// sure is ham, and falls in the band where a second opinion is asked.
pub const CAPPED_SCORE_FLOOR: f64 = 0.5;

#[cfg(test)]
mod tests;
