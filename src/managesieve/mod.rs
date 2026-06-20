//! ManageSieve (RFC 5804): remote management of users' Sieve scripts.
//!
//! A line-based protocol on port 4190 that lets a mail client upload, validate,
//! list, fetch, rename, delete and activate the Sieve filter scripts the
//! delivery pipeline runs. The transport starts in cleartext and requires a
//! STARTTLS upgrade before authentication; SASL PLAIN is then accepted.
//!
//! The protocol (`command`, `session`) and storage (`store`) are sans-IO and
//! unit-tested; `server` is the thin network layer.

pub mod command;
pub mod server;
pub mod session;
pub mod store;
