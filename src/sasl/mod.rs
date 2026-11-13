//! Shared SASL mechanism abstraction.
//!
//! SMTP and IMAP advertise and negotiate the same set of SASL mechanisms under
//! the same conditions (channel binding needs a bound certificate hash; the
//! OAuth mechanisms need a configured verifier). This module is the single
//! source of truth for which mechanisms are available, so the two protocols
//! cannot drift apart — each only formats the shared list in its own syntax.

mod availability;
mod mechanism;
#[cfg(test)]
mod tests;

pub use availability::{available, is_available};
pub use mechanism::Mechanism;
