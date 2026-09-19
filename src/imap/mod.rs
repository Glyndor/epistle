//! IMAP4rev2 server (RFC 9051), read-only core.

pub mod acl;
pub mod archive;
pub mod command;
mod compress;
mod flags;
mod index;
pub mod junk_trainer;
pub mod keyword;
pub mod mailbox;
pub mod metadata;
mod modseq;
mod scan;
pub mod server;
pub mod session;
mod snapshot;
mod subscriptions;
mod uid;
mod uidvalidity;
mod vanished;
