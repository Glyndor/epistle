//! Automatic removal of old mail from Trash, Junk, Rejects and any folder by
//! name.
//!
//! Nothing here runs unless the operator wrote `[storage.cleanup]`. The
//! retention of a folder is a number of days resolved from the operator's
//! rules (narrowest scope first) and the account's own preference, which can
//! only be shorter than an operator's cap (see `combine`). A run removes at most
//! the configured number of messages, remembers where it stopped, and goes on
//! from there at the next run ([`run`]). A message leaves through the same
//! door as an IMAP EXPUNGE, so the archive of `deleted_retention_days`, the
//! QRESYNC log and the JMAP journal all see it.
//!
//! The caller owns the clock: a run is given the time to judge by and must
//! only be started with one the evidence time reference believes
//! ([`crate::evidence::timeref`]). A deletion on a wrong clock cannot be
//! undone.

mod cursor;
mod policy;
mod prefs;
mod run;

pub use policy::{Policy, Subject, combine, folder_keys, resolve, rule_key};
pub use prefs::Prefs;
pub use run::{Counts, Mode, Report, run};

#[cfg(test)]
mod tests;
