//! DKIM startup warning, alert engine and ARC sealer wiring for `serve`.

use std::sync::Arc;

use crate::config::Config;

/// What the single-signature DKIM warning will say at startup, if anything.
/// Returns `None` when there is no warning to log (no `[dkim]` section, or
/// both RSA fields configured). Pulled out of `serve::run` so the message is
/// the only one in the codebase and so a test can assert the wording without
/// binding a socket.
pub(in crate::cli) fn single_signature_dkim_warning(config: &Config) -> Option<String> {
	config
		.dkim
		.as_ref()
		.and_then(|dkim| dkim.single_signature_warning())
}

/// Emit the single-signature DKIM warning through `tracing` at the very top of
/// startup so it lands in the log before any listener binds. A no-op when the
/// helper returns `None`. The same wording is what `config-check` and
/// `verify-dns` write to their `err` sinks through `style::warn_to`.
pub(in crate::cli::serve) fn log_single_signature_dkim_warning(config: &Config) {
	if let Some(warning) = single_signature_dkim_warning(config) {
		tracing::warn!(remedy = "epistle dkim-keygen --rsa", "{warning}");
	}
}

/// Spawn the metric alert engine when `[[alerts]]` is non-empty. A no-op when
/// the config has no rules: no task, no overhead.
///
/// One task per rule owns the snapshot/window/cooldown bookkeeping and posts
/// the configured webhook/email when the rule crosses its threshold. The
/// runner fails open: any dispatch error is logged and the task keeps
/// evaluating on the next tick.
pub(in crate::cli::serve) fn spawn_alert_engine(
	config: &Config,
	metrics: std::sync::Arc<crate::metrics::Metrics>,
	webhook: Option<std::sync::Arc<crate::webhook::Webhook>>,
	spool: std::sync::Arc<crate::storage::FsSpool>,
) {
	if config.alerts.is_empty() {
		return;
	}
	let ctx = crate::alerts::context(
		webhook,
		spool,
		config.hostname.clone(),
		config.system_auto_submitted,
	);
	let _handle = crate::alerts::run(config.alerts.clone(), metrics, ctx);
}

/// Build the optional ARC sealer from `[arc]`: a DKIM-format ed25519 key
/// under the server hostname. Absent config yields `None`; a key that does
/// not load is fatal (fail closed), so a misconfigured sealer never lets
/// mail through unsealed by accident.
pub(in crate::cli::serve) fn build_arc_sealer(
	config: &Config,
) -> std::io::Result<Option<Arc<crate::arc::sealer::ArcSealer>>> {
	let Some(arc) = &config.arc else {
		return Ok(None);
	};
	let key = crate::dkim::load_ed25519_key(&arc.key_file).map_err(std::io::Error::other)?;
	Ok(Some(Arc::new(crate::arc::sealer::ArcSealer::new(
		key,
		config.hostname.clone(),
		arc.selector.clone(),
	))))
}
