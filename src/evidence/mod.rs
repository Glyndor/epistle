//! Mail classes and tamper-evident sending evidence.
//!
//! [`class`] decides what kind of mail a submission is. For the classes that
//! keep evidence, every accepted message and every recipient outcome is
//! appended to a hash-chained log; each closed day is sealed by a signed
//! checkpoint and an RFC 3161 timestamp, so a third party can later check
//! that a message was sent on a given day to given people and that nobody,
//! the operator included, rewrote the record afterwards.

pub mod anchor;
pub mod chain;
pub mod class;
pub mod day;
pub mod lines;
pub mod marketing;
pub mod merkle;
pub mod record;
#[cfg(test)]
pub(crate) mod test_support;
pub mod verify;

pub use class::{CLASS_HEADER, ClassSources, MailClass};
