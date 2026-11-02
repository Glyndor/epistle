//! What `dkim split` would do, from the configuration alone.

use crate::config::Config;

/// The domains that stay on the `[dkim]` key and the ones that move to a
/// key of their own.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
	/// The domain that keeps signing with `[dkim]`, so the key belongs to
	/// exactly one domain when the split is done.
	pub keeps: String,
	/// The domains that get a key of their own, sorted.
	pub moves: Vec<String>,
	/// Whether `[dkim]` signs with an RSA key too, and so do the new keys.
	pub dual_signing: bool,
}

/// Plan the split, `None` when no key signs more than one domain. A rotation
/// in progress refuses it: the rotation has published records for the domains
/// that are about to leave the default key, and it finishes first.
pub(super) fn build(config: &Config) -> Result<Option<Plan>, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	if let Some(pending) = crate::dkim::rotate::read_state(&config.data_dir)
		.map_err(|error| error.to_string())?
		.and_then(|state| state.pending)
	{
		return Err(format!(
			"a rotation to {} is in progress; run `epistle dkim split` when `epistle dkim show` no longer lists it",
			pending.selector
		));
	}
	let mut sharing = dkim.domains_on_default(&config.domains, &config.domain_aliases);
	if sharing.len() < 2 {
		return Ok(None);
	}
	// A configured domain keeps the key before an alias does, and the first
	// one listed before the others, so the choice does not move with the sort.
	let keeps = config
		.domains
		.iter()
		.map(|domain| domain.to_ascii_lowercase())
		.find(|domain| sharing.contains(domain))
		.unwrap_or_else(|| sharing[0].clone());
	sharing.retain(|domain| *domain != keeps);
	Ok(Some(Plan {
		keeps,
		moves: sharing,
		dual_signing: dkim.rsa_selector.is_some() && dkim.rsa_key_file.is_some(),
	}))
}
