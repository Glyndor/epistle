//! DKIM signing and verification (RFC 6376).

pub(crate) mod canon;
pub mod domain_keys;
pub(crate) mod key_record;
mod per_domain;
pub mod rotate;
mod rsa_keygen;
pub mod sharing;
mod sign;
pub(crate) mod signature;
mod spki;
pub mod split_state;
pub mod stale;
mod verify;

#[cfg(test)]
pub(crate) mod test_support;

pub use per_domain::{DomainSigner, PerDomainSigner};
pub use rotate::{
	ROTATE_INTERVAL_DAYS, ROTATE_OVERLAP_DAYS, ReloadableSigner, Rotator, publication_waits,
};
pub use rsa_keygen::{KeygenError, generate_rsa_key};
pub use sign::{Signer, SignerError, generate_key};
pub(crate) use sign::{load_ed25519_key, rsa_record_value};
pub use verify::{DkimOutcome, DkimResult, verify_message};

// Shared with the ARC implementation (RFC 8617 reuses DKIM's algorithm,
// canonicalization, and public-key record format).
pub(crate) use signature::{Algorithm, Canon};
#[cfg(test)]
pub(crate) use spki::spki_for_rsa;
pub(crate) use spki::{rsa_modulus_bits, rsa_public_key_from_spki};

pub(crate) use verify::verify_tlsrpt;

#[cfg(test)]
pub(crate) use verify::header_names;
