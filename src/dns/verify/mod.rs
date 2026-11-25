//! What `epistle verify-dns` and `GET /api/v1/dns/verify` both do: ask the live
//! DNS about the hostname and each hosted domain and report the drift from
//! the records the configuration needs.
//!
//! The command prints each group as it finishes, so it calls the per-group
//! functions; the route calls [`verify`]. Both build the JSON from the same
//! [`Group`] values, so the two cannot answer differently.

use serde_json::{Value, json};

use crate::config::Config;
use crate::dns::{self, Check, Status};
use crate::spf::DnsLookup;

/// One name and the checks made for it: the mail hostname, or one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
	/// The hostname or the domain the checks are about.
	pub name: String,
	/// The checks, in the order they ran.
	pub checks: Vec<Check>,
}

impl Group {
	/// The group as `verify-dns --json` lists it.
	pub fn json(&self) -> Value {
		let checks: Vec<Value> = self
			.checks
			.iter()
			.map(|check| {
				json!({
					"kind": check.kind, "name": check.name,
					"status": status_name(&check.status), "detail": check.detail,
				})
			})
			.collect();
		json!({ "name": self.name, "checks": checks })
	}
}

/// How the JSON spells a status.
pub const fn status_name(status: &Status) -> &'static str {
	match status {
		Status::Ok => "ok",
		Status::Missing => "missing",
		Status::LookupError => "error",
		Status::Skipped => "skipped",
	}
}

/// The result `verify-dns --json` prints: `ok` is false when any expected
/// record is missing (a lookup error is inconclusive, not drift).
pub fn report_json(groups: &[Group]) -> Value {
	let ok = groups.iter().all(|group| dns::all_ok(&group.checks));
	json!({ "ok": ok, "groups": groups.iter().map(Group::json).collect::<Vec<_>>() })
}

/// The default DKIM selectors epistle publishes (the Ed25519 selector
/// plus an optional RSA selector), used to locate the `_domainkey`
/// records when a domain has no `[dkim.domain]` override. The
/// Ed25519 selector is the one the rotator currently has in service
/// when the rotation state file exists, falling back to the configured
/// selector at startup before the first tick has run. The RSA
/// selector follows the same rule through
/// [`crate::dkim::rotate::active_rsa`].
pub fn dkim_default_selectors(
	config: &Config,
) -> Result<Vec<String>, crate::dkim::rotate::RotateError> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let mut selectors = vec![crate::dkim::rotate::active_ed25519(dkim, &config.data_dir)?.selector];
	if let Some(rsa) = crate::dkim::rotate::active_rsa(dkim, &config.data_dir)? {
		selectors.push(rsa.selector);
	}
	Ok(selectors)
}

/// One domain's DKIM selectors, ed25519 plus an optional RSA. The
/// selectors come from `[dkim.domain]` when the configuration has an
/// entry for the domain, otherwise from the default `[dkim]` block.
pub fn dkim_selectors_for(
	config: &Config,
	domain: &str,
) -> Result<Vec<String>, crate::dkim::rotate::RotateError> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	if let Some(entry) = dkim.override_for(domain) {
		return Ok(std::iter::once(entry.selector.clone())
			.chain(entry.rsa_selector.clone())
			.collect());
	}
	dkim_default_selectors(config)
}

/// The checks of the mail hostname: its addresses and their reverse DNS.
pub async fn host_group(
	hostname: &str,
	public_ipv4: Option<std::net::Ipv4Addr>,
	public_ipv6: Option<std::net::Ipv6Addr>,
	dns: &dyn DnsLookup,
) -> Group {
	Group {
		name: hostname.to_string(),
		checks: dns::check_host(hostname, public_ipv4, public_ipv6, dns).await,
	}
}

/// The checks of one domain, whose MX has to name `hostname`.
///
/// A per-domain override replaces the default selectors: the operator's
/// published TXT must match the key the server signs with, so a domain in
/// `[dkim.domain]` cannot be verified against the default ones. A record of
/// a group the configuration skips is not published on purpose, so it is not
/// missing and not drift.
pub async fn domain_group(
	config: &Config,
	hostname: &str,
	domain: &str,
	dns: &dyn DnsLookup,
) -> Result<Group, crate::dkim::rotate::RotateError> {
	let selectors = dkim_selectors_for(config, domain)?;
	let checks = dns::check_domain_for_role(
		domain,
		hostname,
		&selectors,
		config.domain_role(domain),
		dns,
	)
	.await;
	Ok(Group {
		name: domain.to_string(),
		checks: dns::skip::split_checks(checks, &config.skip_set()),
	})
}

/// Check the hostname (when `with_host`) and then `domains`, in that order.
pub async fn verify(
	config: &Config,
	domains: &[String],
	with_host: bool,
	dns: &dyn DnsLookup,
) -> Result<Vec<Group>, crate::dkim::rotate::RotateError> {
	let mut groups = Vec::with_capacity(domains.len() + 1);
	if with_host {
		groups.push(
			host_group(
				&config.hostname,
				config.public_ipv4,
				config.public_ipv6,
				dns,
			)
			.await,
		);
	}
	for domain in domains {
		groups.push(domain_group(config, &config.hostname, domain, dns).await?);
	}
	Ok(groups)
}
