//! Message storage.
//!
//! Messages are stored as individual RFC 5322 files plus a JSON envelope
//! sidecar, written crash-safely (write to a temporary file, fsync, rename).
//! An embedded index and the account/mailbox model build on top of this
//! spool; PostgreSQL stays an option for deployments that need it, but the
//! default install must work with zero external services.

mod crypto;
mod delivery;
mod routing;
mod spool;

pub use crypto::{CryptoError, MessageCrypto, generate_key_base64};
pub use delivery::LocalDelivery;

#[cfg(test)]
#[path = "crypto_e2e_tests.rs"]
mod crypto_e2e_tests;
pub use routing::SplitDelivery;
pub use spool::{Envelope, FsSpool, SpoolEntry};
