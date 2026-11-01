//! The Cloudflare orange-cloud check for `epistle status`. Cloudflare's
//! proxy forwards only HTTP(S), so a mail name whose A, AAAA or CNAME is
//! proxied sends SMTP, submission and IMAP clients to Cloudflare instead
//! of to epistle. The mail names are the mail hostname, every MX target
//! of a hosted domain, and each domain's `autoconfig`, `autodiscover` and
//! `mta-sts` hosts (epistle serves those itself, not Cloudflare). Only
//! the Cloudflare provider reports a proxy state; with any other provider
//! the check does not run.

use std::collections::BTreeSet;

use crate::config::Config;
use crate::dns::lockdown::canonical_name;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

/// The status line for a proxied mail name.
pub fn proxied_message(name: &str) -> String {
	format!(
		"{name} is proxied by Cloudflare (orange cloud): mail clients and other servers cannot reach port 25/465/587/993 through the proxy; set it to DNS only"
	)
}

/// The names whose records must not be proxied, canonical.
pub fn mail_names(domains: &[String], hostname: &str, records: &[DnsRecord]) -> BTreeSet<String> {
	let mut names = BTreeSet::new();
	names.insert(canonical_name(hostname));
	for raw in domains {
		let domain = canonical_name(raw);
		for prefix in ["autoconfig", "autodiscover", "mta-sts"] {
			names.insert(format!("{prefix}.{domain}"));
		}
		for record in records {
			if record.kind == RecordKind::Mx
				&& canonical_name(&record.name) == domain
				&& let Some(target) = record.value.split_whitespace().last()
				&& target != "."
			{
				names.insert(canonical_name(target));
			}
		}
	}
	names
}

/// The mail names with a proxied A, AAAA or CNAME, sorted, each once.
pub fn find_proxied(domains: &[String], hostname: &str, records: &[DnsRecord]) -> Vec<String> {
	let names = mail_names(domains, hostname, records);
	let proxied: BTreeSet<String> = records
		.iter()
		.filter(|r| matches!(r.kind, RecordKind::A | RecordKind::Aaaa | RecordKind::Cname))
		.filter(|r| r.proxied == Some(true))
		.map(|r| canonical_name(&r.name))
		.filter(|name| names.contains(name))
		.collect();
	proxied.into_iter().collect()
}

/// Whether the configured provider is Cloudflare, the one whose proxy
/// state matters; with any other provider the check has nothing to read.
pub fn proxy_aware_provider(config: &Config) -> bool {
	config
		.dns
		.iter()
		.any(|dns| dns.provider.eq_ignore_ascii_case("cloudflare"))
}

/// List `zone` through `provider` and return the proxied mail names of
/// the hosted `domains`.
pub async fn proxied_check(
	provider: &dyn DnsProvider,
	zone: &str,
	domains: &[String],
	hostname: &str,
) -> Result<Vec<String>, ProviderError> {
	let records = provider.list(zone).await?;
	Ok(find_proxied(domains, hostname, &records))
}

#[cfg(test)]
mod tests;
