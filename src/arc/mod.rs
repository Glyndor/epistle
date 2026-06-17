//! ARC — Authenticated Received Chain (RFC 8617).
//!
//! ARC preserves authentication results across intermediaries (mailing lists,
//! forwarders) that legitimately break SPF/DKIM. `chain` extracts and
//! structurally validates the ARC header set; cryptographic verification and
//! sealing build on it.

pub mod ams;
pub mod chain;
pub mod seal;
pub mod sealer;
pub mod signature;
pub mod validate;

#[cfg(test)]
mod ams_tests;
#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod seal_tests;
#[cfg(test)]
mod sealer_tests;
#[cfg(test)]
mod signature_tests;
#[cfg(test)]
mod validate_tests;
