//! IMAP4rev2 server (RFC 9051), read-only core.

pub mod command;
pub mod mailbox;
mod modseq;
pub mod server;
pub mod session;
mod uid;
mod uidvalidity;
mod vanished;
