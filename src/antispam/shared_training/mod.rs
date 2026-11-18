//! The hand-off from the SMTP server to the shared corpus.
//!
//! The server learns from its own decisions: mail it accepts is ham, mail it
//! rejects or quarantines is spam. That mail comes from anyone on the
//! internet, no account needed, so the learning must cost the server a fixed
//! amount however many messages arrive and whatever they hold:
//!
//! - **A bounded queue, a fixed set of workers.** At most
//!   [`QUEUE_CAPACITY`] jobs wait, each holding at most [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES)
//!   of text, and [`WORKERS`] workers write to the database, so the memory is
//!   about 16 MiB and the database never sees more than [`WORKERS`] training
//!   transactions at once. There is no task per message.
//! - **A budget per source, per kind.** Ham and spam are counted apart, so
//!   forged spam cannot use up what a sender may teach as ham. A source is
//!   the client address, by its own block and by the wider block around it
//!   (an IPv4 /32 and /24, an IPv6 /64 and /48), so rotating addresses
//!   inside a block does not buy a new budget; and the sender's domain, but
//!   only when the server verified it. The envelope sender is written by the
//!   client: a domain the server did not verify is never a key, or anyone
//!   could use up the budget of a domain they do not own. Each key allows
//!   [`FINE_PENDING`]/[`COARSE_PENDING`] jobs waiting or running and
//!   [`FINE_PER_WINDOW`]/[`COARSE_PER_WINDOW`] per [`WINDOW`].
//! - **A share of the server's budget per network.** The whole server
//!   accepts [`GLOBAL_PER_WINDOW`] jobs per kind and window, and one network
//!   (an IPv4 /16, an IPv6 /32) may take at most [`BLOCK_PER_WINDOW`] of
//!   them, a sixteenth, and may have [`NETWORK_PENDING`] jobs waiting or
//!   running over ham and spam together, a quarter of the queue. A job with
//!   no address counts as a network of its own with [`UNATTRIBUTED_PENDING`]. The last quarter of the global budget is kept for
//!   networks that have used at most [`FIRST_JOBS`] of their share: past
//!   that, a network is held back once [`SOFT_LIMIT`] is reached, while a
//!   network under its fair share keeps training until the global budget is
//!   truly spent.
//! - **Tables that cannot be filled.** Addresses, domains and networks live
//!   in separate tables of [`TABLE_SIZE`] entries each. A full table drops
//!   its least recently used entry to make room, so a flood of new keys only
//!   makes the table forget old ones, never refuses a new source; and it
//!   cannot push a domain out by rotating addresses. A forgotten key starts
//!   again from nothing, which costs the attacker nothing it did not already
//!   have: the wider keys and the global count it is also counted under
//!   remember it.
//! - **Never blocks.** [`SharedTraining::submit`] does not wait: a job that
//!   does not fit is dropped and the caller counts it. Learning is advisory;
//!   the SMTP reply never depends on it.
//!
//! The corpus cannot tell a message the attacker chose from one it should
//! learn, so the budget is the defence: what any source can teach the shared
//! corpus per hour is capped, and the server only teaches it ham from
//! senders it verified (see `Server::train_corpus`).
//!
//! # Invariants
//!
//! 1. No source can take from another more than that other's reserved part:
//!    one network never takes more than [`BLOCK_PER_WINDOW`] of the global
//!    budget in a window, never has more than [`NETWORK_PENDING`] jobs in
//!    flight (ham and spam together), and the last quarter of the global
//!    budget can be spent only by networks at or under [`FIRST_JOBS`]. So a
//!    network that uses at most [`FIRST_JOBS`] jobs a window trains whenever
//!    the other networks, each held to [`BLOCK_PER_WINDOW`], have not between
//!    them spent it all, which takes more than fifteen of them. Jobs with no
//!    address are one network of their own, held to [`UNATTRIBUTED_PENDING`]
//!    in flight and to the soft limit.
//! 2. The global budget is never exceeded: per kind and window, at most
//!    [`GLOBAL_PER_WINDOW`] jobs are admitted, at most [`BLOCK_PER_WINDOW`]
//!    of them from one network (for as long as the network stays in its
//!    table, which takes [`TABLE_SIZE`] other networks pushing it out).
//! 3. Memory is bounded: each table holds at most [`TABLE_SIZE`] keys, a key
//!    is at most a few hundred bytes, and the queue holds
//!    [`QUEUE_CAPACITY`] jobs of at most [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES).
//! 4. Refusing is cheap and leaves no state: a refused job costs a few hash
//!    lookups and changes nothing, not a count, not the order of use, not a
//!    window, and a job the queue has no room for is turned away before the
//!    budget is charged. Admitting costs a few hash lookups and ordered-map
//!    steps.

mod budget;
mod queue;
mod source;
mod table;

use super::corpus::BayesStore;

pub use budget::{
	BLOCK_PER_WINDOW, Budget, COARSE_PENDING, COARSE_PER_WINDOW, Charge, FINE_PENDING,
	FINE_PER_WINDOW, FIRST_JOBS, GLOBAL_PER_WINDOW, NETWORK_PENDING, Refusal, SOFT_LIMIT,
	TABLE_SIZE, UNATTRIBUTED_PENDING, WINDOW,
};
pub use queue::{Job, QUEUE_CAPACITY, SharedTraining, WORKERS, run_worker};
pub use source::TrainSource;

#[cfg(test)]
use source::MAX_DOMAIN_LEN;

#[cfg(test)]
mod tests;
