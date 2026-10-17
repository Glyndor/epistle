//! RFC 3161 timestamps for checkpoints.
//!
//! A checkpoint's SHA-256 is sent to a timestamp authority, and the signed
//! response is kept next to the checkpoint as `DAY.tsr`. Nothing else is
//! ever sent: not a record, not an address, not a byte of mail. The token
//! proves that the checkpoint, and so every record it seals, existed at the
//! time the authority stamped, in a form anyone can check with
//! `openssl ts -verify`.
//!
//! The DER is read by [`der`], a strict reader written for the few
//! structures RFC 3161 uses; certificates are parsed by `x509-parser` and
//! signatures checked by `ring`, both already dependencies of the server.

pub mod client;
pub mod der;
#[cfg(test)]
pub(crate) mod fake;
pub mod keys;
pub mod oid;
pub mod request;
pub mod settings;
pub mod stamp;
pub mod token;
pub mod verify;

pub use verify::{
	Check, Expected, Outcome, Report, Stamp, VerifyError, check, verify, verify_expected,
};
