//! Construction of the [`SplitDelivery`] sink and its four delivery-path
//! companions: DKIM signer, SRS, webhook and ARC sealer. Pulled out of
//! `serve` because every feature that touches outbound mail added five
//! more lines to that file, and the cost belongs here, not at the top of
//! the startup flow.

use std::sync::Arc;

use crate::config::Config;
use crate::directory_store::DirectoryHandle;
use crate::metrics::Metrics;
use crate::storage::{MessageCrypto, SplitDelivery};

/// Everything `serve` needs after wiring the split delivery sink: the sink
/// itself, the default DKIM signer (consumed by the rotation task), the
/// optional webhook (consumed by the queue worker and the alert engine),
/// and the optional ARC sealer (consumed by each SMTP listener).
pub(in crate::cli) struct SplitCompanions {
	/// The split delivery sink, wrapped in an `Arc` by the caller.
	pub split: SplitDelivery,
	/// The default DKIM signer, present when `[dkim]` is configured.
	/// The rotation task replaces it; per-domain overrides, when any
	/// are configured, are loaded into the sink but not rotated.
	pub dkim_signer: Option<crate::dkim::ReloadableSigner>,
	/// The webhook dispatcher, present when `[webhook]` is configured.
	pub webhook: Option<Arc<crate::webhook::Webhook>>,
	/// The ARC sealer, present when `[arc]` is configured.
	pub arc_sealer: Option<Arc<crate::arc::sealer::ArcSealer>>,
	/// The evidence service and the class bindings.
	pub evidence: super::evidence::Evidence,
}

/// Load every per-domain DKIM override from the configuration: each
/// ed25519 key, plus the optional RSA pair. A bad path or unreadable
/// key stops the start, the same way a bad configured `[dkim]` key
/// does, so the misconfiguration cannot ship.
fn load_per_domain_signers(
	dkim: &crate::config::Dkim,
) -> std::io::Result<Vec<crate::dkim::DomainSigner>> {
	let mut loaded = Vec::with_capacity(dkim.domain.len());
	for entry in &dkim.domain {
		let mut signer = crate::dkim::Signer::load(&entry.selector, &entry.key_file)
			.map_err(std::io::Error::other)?;
		if let (Some(rsa_selector), Some(rsa_key_file)) = (&entry.rsa_selector, &entry.rsa_key_file)
		{
			signer = signer
				.with_rsa(rsa_selector, rsa_key_file)
				.map_err(std::io::Error::other)?;
		}
		loaded.push(crate::dkim::DomainSigner {
			domain: entry.name.to_ascii_lowercase(),
			signer: Arc::new(signer),
		});
	}
	Ok(loaded)
}

/// Build [`SplitDelivery`] and attach the DKIM signer, SRS, webhook, and
/// ARC sealer. Keep this order, because it is the order in which a bad
/// configuration stops the start: a missing `[dkim]` key before SRS, the
/// webhook and ARC are attempted, a bad webhook URL before ARC, and a bad
/// ARC key before the sink is returned.
pub(in crate::cli) fn build_split_with_companions(
	config: &Config,
	metrics: &Arc<Metrics>,
	directory: DirectoryHandle,
	crypto: MessageCrypto,
) -> std::io::Result<SplitCompanions> {
	let evidence = super::evidence::open(config, &crypto)?;
	let mut split = SplitDelivery::new_with_crypto(&config.data_dir, directory, crypto)?
		.with_evidence(Arc::clone(&evidence.service))
		.with_rules(config.rules.clone())
		.with_identification(crate::smtp::identification::Policy::from_config(config))
		.with_metrics(metrics.clone());
	let mut dkim_signer: Option<crate::dkim::ReloadableSigner> = None;
	if let Some(dkim) = &config.dkim {
		let active = crate::dkim::rotate::active_ed25519(dkim, &config.data_dir)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		let mut signer = crate::dkim::Signer::load(&active.selector, &active.key_file)
			.map_err(std::io::Error::other)?;
		let rsa = crate::dkim::rotate::active_rsa(dkim, &config.data_dir)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		if let Some(rsa) = rsa {
			signer = signer
				.with_rsa(&rsa.selector, &rsa.key_file)
				.map_err(std::io::Error::other)?;
		}
		let reloadable = crate::dkim::ReloadableSigner::new(Arc::new(signer));
		let overrides = load_per_domain_signers(dkim)?;
		let per_domain = crate::dkim::PerDomainSigner::new(reloadable.clone(), overrides);
		split = split.with_signer(per_domain);
		dkim_signer = Some(reloadable);
	}
	if let Some(secret) = &config.srs_secret {
		let srs = crate::queue::srs::Srs::new(secret.as_bytes());
		split = split.with_srs(srs, config.hostname.clone());
	}
	// A destination the webhook client refuses leaves the server without a
	// webhook and says so: the webhook is advisory, and a configuration that
	// loaded before the destination policy must still start the server.
	let webhook = match config.active_webhook().map(crate::webhook::poster) {
		Some(Ok(webhook)) => Some(Arc::new(webhook.with_metrics(metrics.clone()))),
		Some(Err(error)) => {
			tracing::warn!(%error, "the webhook cannot be used and no event will be sent");
			None
		}
		None => None,
	};
	if let Some(webhook) = &webhook {
		split = split.with_webhook(Arc::clone(webhook));
	}
	let arc_sealer = super::tasks::build_arc_sealer(config)?;
	if let Some(sealer) = &arc_sealer {
		split = split.with_arc_sealer(Arc::clone(sealer));
	}
	Ok(SplitCompanions {
		split,
		dkim_signer,
		webhook,
		arc_sealer,
		evidence,
	})
}

#[cfg(test)]
mod tests;
