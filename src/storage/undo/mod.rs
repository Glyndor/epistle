//! Undo send: a submission by an authenticated account waits on disk for a
//! configured time before anything is delivered, and its sender can take it
//! back until then.
//!
//! The hold sits at the submission boundary, in front of the routing sink,
//! because that sink delivers local recipients at once: a hold in the
//! outbound spool alone would leave them out. A held submission is a file in
//! [`UndoStore`] with a release time; nothing sleeps. [`UndoSink`] writes it,
//! [`Releaser`] hands it to the routing sink when its time comes (and after
//! a restart, for what was waiting), and [`UndoStore::cancel`] removes it.
//! Only mail an account submits is ever held: not mail from elsewhere, not
//! the reports and bounces the server writes. See [`crate::config::UndoSend`]
//! for the settings.

mod frame;
mod policy;
mod release;
mod sink;
mod store;

pub use frame::Held;
pub use policy::UndoPolicy;
pub use release::{NoticeStyle, Pass, Releaser};
pub use sink::UndoSink;
pub use store::{CancelError, Canceller, Pending, RELEASED_KEPT_SECS, TakenBack, UndoStore};

#[cfg(test)]
mod tests;
