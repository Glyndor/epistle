//! `[oauth]` with a `signing_key`: the key must be the private half of
//! `public_key`. The verifier reads every token it accepts as one the
//! built-in authorization server issued, so a `public_key` that belongs to
//! somebody else's provider would hand that provider's users the accounts
//! their `sub` names. Refusing the pair at load time keeps that mistake from
//! ever being served.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::Oauth;

impl Oauth {
	/// `Ok` without a signing key, or when the signing key is the private
	/// half of `public_key`. A `signing_key_file` that cannot be read is left
	/// for the start of the server, which refuses it.
	pub fn check_signing_pair(&self) -> Result<(), String> {
		let Ok(Some(material)) = self.signing_key_material() else {
			return Ok(());
		};
		let Some(public) = &self.public_key else {
			return Ok(());
		};
		let invalid = || {
			"`[oauth] signing_key` is not a base64 PKCS#8 ES256 private key (see `epistle oauth-keygen`)".to_string()
		};
		let pkcs8 = BASE64.decode(material.trim()).map_err(|_| invalid())?;
		let pair = EcdsaKeyPair::from_pkcs8(
			&ECDSA_P256_SHA256_FIXED_SIGNING,
			&pkcs8,
			&SystemRandom::new(),
		)
		.map_err(|_| invalid())?;
		let configured = BASE64.decode(public.trim()).unwrap_or_default();
		if pair.public_key().as_ref() != configured.as_slice() {
			return Err("`[oauth] signing_key` is not the private half of `public_key`: with a signing key every token is read as one this server issued, so `public_key` must be the matching public point (see `epistle oauth-keygen`)".to_string());
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "oauth_pair_tests.rs"]
mod tests;
