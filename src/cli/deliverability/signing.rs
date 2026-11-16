//! The DKIM signer the running server signs with, loaded from the same
//! configuration and rotation state.

use std::sync::Arc;

use crate::config::Config;
use crate::dkim::{PerDomainSigner, ReloadableSigner, Signer};

/// Load the signer: the `[dkim]` default plus every per-domain key. `None`
/// when `[dkim]` is not configured, so the message goes unsigned and the
/// report says so.
pub(super) fn load(config: &Config) -> std::io::Result<Option<PerDomainSigner>> {
	let Some(dkim) = &config.dkim else {
		return Ok(None);
	};
	let invalid = |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error);
	let active = crate::dkim::rotate::active_ed25519(dkim, &config.data_dir).map_err(invalid)?;
	let mut signer =
		Signer::load(&active.selector, &active.key_file).map_err(std::io::Error::other)?;
	if let Some(rsa) = crate::dkim::rotate::active_rsa(dkim, &config.data_dir).map_err(invalid)? {
		signer = signer
			.with_rsa(&rsa.selector, &rsa.key_file)
			.map_err(std::io::Error::other)?;
	}
	let overrides = crate::cli::serve::dkim::load_per_domain_signers(dkim, &config.data_dir)?;
	Ok(Some(PerDomainSigner::new(
		ReloadableSigner::new(Arc::new(signer)),
		overrides,
	)))
}
