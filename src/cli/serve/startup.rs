//! Small startup operations shared by the listener orchestration.

use crate::config::Config;
use std::sync::Arc;

pub(super) fn api_keys(config: &Config) -> Arc<crate::api::ApiKeySet> {
	Arc::new(
		crate::api::ApiKeySet::open(&config.data_dir)
			.unwrap_or_else(|error| {
				tracing::warn!(%error, "api_keys.toml unreadable at startup; no API keys loaded until it is fixed");
				crate::api::ApiKeySet::empty()
			}),
	)
}

pub(super) fn ipv4_any_ports(config: &Config) -> std::collections::HashSet<u16> {
	config
		.listeners
		.iter()
		.filter(|l| matches!(l.addr, std::net::IpAddr::V4(v4) if v4.is_unspecified()))
		.map(|l| l.socket_addr().port())
		.collect()
}

pub(super) fn subjectpass(
	config: &Config,
	has_database: bool,
) -> std::io::Result<Option<crate::antispam::subjectpass::SubjectPass>> {
	if !config.subjectpass.enabled || !has_database {
		return Ok(None);
	}
	crate::antispam::subjectpass::SubjectPass::open(&config.data_dir)
		.map(Some)
		.inspect_err(|error| eprintln!("error: cannot open subjectpass key: {error}"))
}
