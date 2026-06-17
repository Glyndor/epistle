//! ARC — Authenticated Received Chain (RFC 8617).
//!
//! ARC preserves authentication results across intermediaries (mailing lists,
//! forwarders) that legitimately break SPF/DKIM. `chain` extracts and
//! structurally validates the ARC header set; cryptographic verification and
//! sealing build on it.

pub mod chain;

#[cfg(test)]
mod chain_tests;
