//! The hosted-domain state of `serve`: written from the configuration file
//! at the first start, then reloaded whenever `<data_dir>/domains.toml`
//! changes, with every part of the server that reads the hosted domains while
//! it runs following the reloads.

use std::sync::Arc;

use crate::config::Config;
use crate::directory_store::{AccountStore, HostedDomains};
use crate::domain::state::DomainsFile;
use crate::editable::LiveConfig;

/// Write the state file when it does not exist yet, so every later write
/// changes the file this server reloads, and build the live configuration
/// that follows it.
pub(super) fn start(config: &Config) -> Arc<LiveConfig> {
	match crate::domain::state::edit::seed(config) {
		Ok(true) => tracing::info!(
			file = %crate::domain::state::path(&config.data_dir).display(),
			"wrote the hosted domains of the configuration file to the domain state file"
		),
		Ok(false) => {}
		// The server still runs with the domains it loaded; the next write
		// creates the file.
		Err(error) => tracing::warn!(%error, "cannot write the domain state file"),
	}
	match crate::aliases::edit::seed(config) {
		Ok(true) => tracing::info!(
			file = %crate::aliases::path(&config.data_dir).display(),
			"wrote the aliases of the configuration file to the alias state file"
		),
		Ok(false) => {}
		Err(error) => tracing::warn!(%error, "cannot write the alias state file"),
	}
	let live = LiveConfig::new(config.clone());
	live.track::<DomainsFile>();
	live.track::<crate::aliases::AliasesFile>();
	live
}

/// What follows the hosted domains besides the API and the client set-up
/// documents, which subscribe on their own.
pub(super) struct Followers {
	/// The account store behind every recipient, sender and login check.
	pub account_store: Arc<AccountStore>,
	/// The DKIM signer of the sink, when `[dkim]` is configured.
	pub signer: Option<crate::dkim::PerDomainSigner>,
	/// The SRS keys of the sink.
	pub srs: crate::storage::SrsSlot,
}

/// Make `followers` follow every reload of `live`.
pub(super) fn follow(live: &LiveConfig, followers: Followers) {
	let Followers {
		account_store,
		signer,
		srs,
	} = followers;
	live.on_change(move |config| {
		account_store.reload_domains(HostedDomains::of(config));
		account_store.reload_aliases(config.alias.clone());
	});
	live.on_change(move |config| {
		let keys = config
			.srs_enabled()
			.then(|| (config.srs_keys(), config.hostname.clone()));
		srs.replace(keys);
	});
	if let Some(signer) = signer {
		live.on_change(move |config| reload_signers(&signer, config));
	}
}

/// Give the signer one override per `[[dkim.domain]]` entry of `config`. An
/// override the signer already holds is kept, with whatever its rotation
/// made of it; a new one is loaded. A key that does not load is logged and
/// the domain signs with the `[dkim]` key until it does.
fn reload_signers(signer: &crate::dkim::PerDomainSigner, config: &Config) {
	let Some(dkim) = &config.dkim else {
		return;
	};
	let current = signer.overrides();
	let mut next = Vec::with_capacity(dkim.domain.len());
	for entry in &dkim.domain {
		let name = entry.name.to_ascii_lowercase();
		if let Some(kept) = current.iter().find(|held| held.domain == name) {
			next.push(kept.clone());
			continue;
		}
		match super::dkim::load_domain_signer(entry, &config.data_dir) {
			Ok(loaded) => next.push(loaded),
			Err(error) => tracing::error!(
				domain = %name,
				%error,
				"the DKIM key of the domain does not load; it signs with the [dkim] key"
			),
		}
	}
	signer.replace_overrides(next);
}

#[cfg(test)]
mod tests;
