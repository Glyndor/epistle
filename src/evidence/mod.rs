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
pub mod chain;
pub mod checkpoint;
pub mod class;
pub mod day;
#[cfg(test)]
mod end_to_end_tests;
mod final_break;
pub mod head;
pub mod key;
pub mod lines;
pub mod marketing;
pub mod merkle;
pub mod policy;
pub mod record;
pub mod retention;
pub mod rotation;
pub mod service;
pub mod submission;
pub mod tasks;
#[cfg(test)]
pub(crate) mod test_support;
pub mod timeref;
pub mod tsa;
#[cfg(test)]
mod vectors_tests;
pub mod verify;

pub use class::{CLASS_HEADER, ClassSources, MailClass};
