//! The RSA half of a dual-signing rotation.
//!
//! The RSA key rotates in the same journal entry as the ed25519 key and
//! switches in the same commit. Both keys are generated, published and
//! confirmed before either signs; a failure on either side withdraws both,
//! so the signer never pairs a new key with one receivers cannot look up.

use super::{Pending, RotationState, Rotator, RsaKey};

/// Generates an RSA key: `(PKCS#8 PEM, DKIM TXT value)`, or why it failed.
pub(crate) type RsaKeygen = fn() -> Result<(String, String), String>;

/// The production generator: a 2048-bit key, the size `dkim-keygen --rsa`
/// writes by default.
pub(super) fn rsa_2048() -> Result<(String, String), String> {
	super::super::generate_rsa_key(2048).map_err(|error| error.to_string())
}

/// The selectors a pending rotation publishes: the ed25519 one, then the
/// RSA one when it rotates the RSA key too.
pub(super) fn pending_selectors(pending: &Pending) -> Vec<&str> {
	let mut selectors = vec![pending.selector.as_str()];
	selectors.extend(pending.rsa.as_ref().map(|rsa| rsa.selector.as_str()));
	selectors
}

impl Rotator {
	/// Use `keygen` instead of the default generator for the RSA keys this
	/// rotator generates.
	#[cfg(test)]
	pub(crate) fn with_rsa_keygen(mut self, keygen: RsaKeygen) -> Self {
		self.rsa_keygen = keygen;
		self
	}

	/// The TXT value of the pending RSA key, generating and writing the key
	/// first when no file that loads exists (a file that loads is the one a
	/// killed run wrote and may already have published). `Ok(None)` when
	/// the rotation does not cover RSA. `Err` names why the rotation has to
	/// be withdrawn: the key cannot be made, or the server stopped
	/// dual-signing while the rotation ran.
	pub(super) fn pending_rsa_key(&self, pending: &Pending) -> Result<Option<String>, String> {
		let Some(rsa) = &pending.rsa else {
			return Ok(None);
		};
		if self.signer.current().rsa_selector().is_none() {
			return Err(format!(
				"RSA dual signing was turned off while the rotation to {} ran",
				rsa.selector
			));
		}
		if let Ok(txt) = super::super::rsa_record_value(&rsa.key_file) {
			return Ok(Some(txt));
		}
		let (pem, txt) = (self.rsa_keygen)()
			.map_err(|error| format!("generate the RSA key for {}: {error}", rsa.selector))?;
		super::steps::write_key(&rsa.key_file, &pem)
			.map_err(|error| format!("write the RSA key for {}: {error}", rsa.selector))?;
		Ok(Some(txt))
	}

	/// The RSA key the committed state names, and the one it retires with
	/// the previous selector. A rotation that covered RSA puts its key in
	/// service and retires the one the state named (the configured key, not
	/// named by the state, is left alone). A rotation begun before dual
	/// signing was turned on keeps the RSA key that signs now. Without dual
	/// signing the state stops naming an RSA key and retires it.
	pub(super) fn rsa_after_commit(
		&self,
		state: &RotationState,
		pending: &Pending,
	) -> (Option<RsaKey>, Option<RsaKey>) {
		if pending.rsa.is_none() && self.signer.current().rsa_selector().is_some() {
			return (state.rsa.clone(), None);
		}
		let retired = state.rsa.clone().map(|rsa| RsaKey {
			key_file: self.data_dir.join(rsa.key_file),
			selector: rsa.selector,
		});
		(pending.rsa.clone(), retired)
	}
}
