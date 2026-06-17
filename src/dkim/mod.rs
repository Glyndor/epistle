//! DKIM signing and verification (RFC 6376).

pub(crate) mod canon;
mod sign;
mod signature;
mod verify;

pub use sign::{Signer, SignerError, generate_key};
pub use verify::{DkimOutcome, DkimResult, verify_message};

// Shared with the ARC implementation (RFC 8617 reuses DKIM's algorithm,
// canonicalization, and public-key record format).
pub(crate) use signature::{Algorithm, Canon};
pub(crate) use verify::parse_key;
