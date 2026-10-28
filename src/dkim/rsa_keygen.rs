//! RSA DKIM key generation, in process.
//!
//! `epistle dkim-keygen --rsa`, `epistle init` and the rotation of the
//! RSA dual-signing key all call [`generate_rsa_key`]. The key is made
//! with `aws-lc-rs`, the TLS provider `rustls` already installs, so
//! nothing has to be on `PATH`: the image the stack runs ships no
//! `openssl`, and a rotation that shelled out to it failed on the
//! first start of every install with a `[dns]` provider configured
//! (Glyndor/epistle#1376).
//!
//! The key that comes out is validated through `ring`'s PKCS#8 loader
//! — the loader the outbound signer uses — before it is written or
//! printed, so a key the signer cannot sign with never reaches the
//! disk.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Generate an RSA DKIM key of `bits` bits, returning the PEM and the
/// matching DKIM DNS record value (`v=DKIM1; k=rsa; p=<base64 SPKI>`).
///
/// `bits` must be 2048 or 4096: the two sizes `dkim-keygen --rsa`
/// accepts, and the only one the rotation asks for.
pub fn generate_rsa_key(bits: u32) -> Result<(String, String), KeygenError> {
	use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
	use aws_lc_rs::rsa::{KeySize, PrivateDecryptingKey};
	use ring::signature::{KeyPair, RsaKeyPair};

	let size = match bits {
		2048 => KeySize::Rsa2048,
		4096 => KeySize::Rsa4096,
		_ => return Err(KeygenError::UnsupportedBits(bits)),
	};
	let key = PrivateDecryptingKey::generate(size).map_err(|_| KeygenError::GenerateFailed)?;
	let der =
		AsDer::<Pkcs8V1Der<'static>>::as_der(&key).map_err(|_| KeygenError::GenerateFailed)?;
	// Validate through ring before we trust the bytes: the rendered record
	// has to come from a key we can actually sign with.
	let pair = RsaKeyPair::from_pkcs8(der.as_ref()).map_err(|_| KeygenError::InvalidKey)?;
	let pkcs1 = pair.public_key().as_ref();
	// The SPKI envelope is the fixed one DKIM's `p=` value carries.
	let spki = super::spki::spki_for_rsa(pkcs1);
	Ok((
		super::sign::pem_encode(der.as_ref()),
		format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki)),
	))
}

/// Errors from the RSA keygen path. Each variant owns its own message so
/// the CLI can `eprintln!` without an intermediate formatting step (and
/// without a taint analyser reading a constant string into a key sink).
#[derive(Debug)]
pub enum KeygenError {
	/// The requested key size is not one the generator makes.
	UnsupportedBits(u32),
	/// The in-process generator could not produce a key.
	GenerateFailed,
	/// The PEM is not an RSA PKCS#8 key `ring` loads.
	InvalidKey,
}

impl std::fmt::Display for KeygenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			KeygenError::UnsupportedBits(bits) => {
				write!(f, "an RSA key of {bits} bits cannot be made (2048 or 4096)")
			}
			KeygenError::GenerateFailed => f.write_str("the RSA key generator produced no key"),
			KeygenError::InvalidKey => {
				f.write_str("the RSA key that was generated is not a valid PKCS#8 RSA key")
			}
		}
	}
}
