//! DANE for SMTP (RFC 6698, RFC 7671, RFC 7672): authenticate TLS via
//! DNSSEC-validated TLSA records instead of (or alongside) the public CA set.

pub mod policy;
pub mod tlsa;
