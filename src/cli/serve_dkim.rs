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
/// itself, the optional DKIM signer (consumed by the rotation task), the
/// optional webhook (consumed by the queue worker and the alert engine),
/// and the optional ARC sealer (consumed by each SMTP listener).
pub(super) struct SplitCompanions {
	/// The split delivery sink, wrapped in an `Arc` by the caller.
	pub split: SplitDelivery,
	/// The hot-swappable DKIM signer, present when `[dkim]` is configured.
	pub dkim_signer: Option<crate::dkim::ReloadableSigner>,
	/// The webhook dispatcher, present when `[webhook]` is configured.
	pub webhook: Option<Arc<crate::webhook::Webhook>>,
	/// The ARC sealer, present when `[arc]` is configured.
	pub arc_sealer: Option<Arc<crate::arc::sealer::ArcSealer>>,
}

/// Build [`SplitDelivery`] and attach the DKIM signer, SRS, webhook, and
/// ARC sealer in the order they were wired inside `serve`. Failures surface
/// in the same order as before the extraction: a missing `[dkim]` key stops
/// the start before SRS / webhook / ARC are even attempted, a bad webhook
/// URL stops before ARC, and a bad ARC key stops before the sink is
/// returned. Errors carry the same text as the inline implementation.
pub(super) fn build_split_with_companions(
	config: &Config,
	metrics: &Arc<Metrics>,
	directory: DirectoryHandle,
	crypto: MessageCrypto,
) -> std::io::Result<SplitCompanions> {
	let mut split = SplitDelivery::new_with_crypto(&config.data_dir, directory, crypto)?
		.with_rules(config.rules.clone())
		.with_metrics(metrics.clone());
	let mut dkim_signer: Option<crate::dkim::ReloadableSigner> = None;
	if let Some(dkim) = &config.dkim {
		let mut signer = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file)
			.map_err(std::io::Error::other)?;
		if let (Some(selector), Some(key_file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
			signer = signer
				.with_rsa(selector, key_file)
				.map_err(std::io::Error::other)?;
		}
		let reloadable = crate::dkim::ReloadableSigner::new(Arc::new(signer));
		split = split.with_signer(reloadable.clone());
		dkim_signer = Some(reloadable);
	}
	if let Some(secret) = &config.srs_secret {
		let srs = crate::queue::srs::Srs::new(secret.as_bytes());
		split = split.with_srs(srs, config.hostname.clone());
	}
	let webhook = match &config.webhook {
		Some(webhook) => Some(Arc::new(
			crate::webhook::Webhook::new(&webhook.url, webhook.secret.clone())
				.map_err(std::io::Error::other)?
				.with_metrics(metrics.clone()),
		)),
		None => None,
	};
	if let Some(webhook) = &webhook {
		split = split.with_webhook(Arc::clone(webhook));
	}
	let arc_sealer = super::serve_tasks::build_arc_sealer(config)?;
	if let Some(sealer) = &arc_sealer {
		split = split.with_arc_sealer(Arc::clone(sealer));
	}
	Ok(SplitCompanions {
		split,
		dkim_signer,
		webhook,
		arc_sealer,
	})
}
