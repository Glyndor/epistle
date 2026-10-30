//! Mail classes and tamper-evident sending evidence.
//!
//! [`class`] decides what kind of mail a submission is. For the classes that
//! keep evidence, every accepted message and every recipient outcome is
//! appended to a hash-chained log; each closed day is sealed by a signed
//! checkpoint and an RFC 3161 timestamp, so a third party can later check
//! that a message was sent on a given day to given people and that nobody,
//! the operator included, rewrote the record afterwards.

pub mod ack;
pub mod anchor;
pub mod audit;
pub mod bindings;
pub mod bundle;
pub mod cancel;
pub mod chain;
pub mod checkpoint;
pub mod class;
pub mod clock_accept;
pub mod day;
mod final_break;
pub mod head;
pub mod hidden;
pub mod key;
pub mod lines;
pub mod marketing;
pub mod merkle;
pub mod policy;
pub mod quota;
pub mod record;
pub mod retention;
pub mod rotation;
pub mod service;
pub mod submission;
pub mod tasks;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
pub mod timeref;
pub mod tsa;
pub mod verify;

pub use class::{CLASS_HEADER, ClassSources, MailClass};
