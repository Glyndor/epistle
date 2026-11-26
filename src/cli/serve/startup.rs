//! Small startup operations shared by the listener orchestration.

use super::{ServeRole, tasks};
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

/// Where the DKIM rotations write their records in this role.
///
/// The certificates container holds the DNS credential, so the `mail` role
/// holds none: its rotations publish through the hand-off the other
/// container serves, and the keys stay where they are.
pub(super) fn dns_write_for_role(role: ServeRole, data_dir: &std::path::Path) -> tasks::DnsWrite {
	match role {
		ServeRole::All => tasks::DnsWrite::Direct,
		ServeRole::Mail => tasks::DnsWrite::Handoff(crate::dns::handoff::dir(data_dir)),
		ServeRole::Certs => tasks::DnsWrite::Direct,
	}
}

/// Start the DKIM rotations, the server's and each domain's.
pub(super) fn spawn_rotations(
	config: &Config,
	role: ServeRole,
	dkim_signer: &Option<crate::dkim::ReloadableSigner>,
	domain_signers: &[crate::dkim::DomainSigner],
	webhook: Option<&Arc<crate::webhook::Webhook>>,
) {
	if !(role.writes_dns() || config.dkim.is_some()) {
		return;
	}
	// The rotations publish their records through the provider this process
	// holds, or, with the certificates container on, through the hand-off the
	// other container serves: that one holds the DNS credential, and this one
	// holds the keys.
	let write = dns_write_for_role(role, &config.data_dir);
	tasks::spawn_dkim_rotation(config, dkim_signer, webhook.map(Arc::clone), &write);
	tasks::spawn_domain_rotations(config, domain_signers, webhook.map(Arc::clone), &write);
}
