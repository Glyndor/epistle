//! The ban policy the running server reads from the operator's
//! configuration. Kept apart from `serve.rs` so the per-file code-line
//! budget stays under the limit: a single helper keeps the wiring
//! tight and the policy contract in one place.

use crate::config::Config;

/// Build the [`BanPolicy`] the running server hands to the
/// [`PgBanStore`]. The operator's `[limits]` `known-network-window`
/// overrides the built-in default; absent keeps the 30-day window the
/// product ships with. The rest of the policy stays at the defaults
/// the production store was tested against.
pub(super) fn ban_policy_for(config: &Config) -> crate::antispam::bans::BanPolicy {
	let default = crate::antispam::bans::BanPolicy::default();
	crate::antispam::bans::BanPolicy {
		known_network_window_secs: config
			.known_network_window_secs
			.unwrap_or(default.known_network_window_secs),
		..default
	}
}

/// The store of bans and known networks over `pool`, with the policy of the
/// operator's configuration.
pub(super) fn pg_ban_store(
	pool: &sqlx::PgPool,
	metrics: &std::sync::Arc<crate::metrics::Metrics>,
	policy: crate::antispam::bans::BanPolicy,
) -> std::sync::Arc<dyn crate::antispam::bans::BanStore> {
	std::sync::Arc::new(crate::antispam::bans::PgBanStore::with_policy(
		pool.clone(),
		Some(metrics.clone()),
		policy,
	))
}
