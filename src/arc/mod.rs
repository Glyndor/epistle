//! ARC — Authenticated Received Chain (RFC 8617).
//!
//! ARC preserves authentication results across intermediaries (mailing lists,
//! forwarders) that legitimately break SPF/DKIM. `chain` extracts and
//! structurally validates the ARC header set; cryptographic verification and
//! sealing build on it.

pub mod ams;
pub mod chain;
pub(crate) mod key;
pub mod seal;
pub mod sealer;
pub mod signature;
pub mod validate;

#[cfg(test)]
pub(crate) use ams::header_names;

#[cfg(test)]
mod tests;
