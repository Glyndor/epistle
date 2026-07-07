//! IMAP4rev2 server (RFC 9051), read-only core.

pub mod acl;
pub mod command;
mod index;
pub mod mailbox;
pub mod metadata;
mod modseq;
pub mod server;
pub mod session;
mod uid;
mod uidvalidity;
mod vanished;
