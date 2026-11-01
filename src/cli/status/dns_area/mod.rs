//! The `dns` check: published records against what epistle expects, reusing
//! the `verify-dns` checks, plus the DKIM public key against the key the
//! server actually signs with.

use std::net::IpAddr;
use std::sync::Arc;

use super::dns_dkim::{SigningKey, compare, signing_keys, state_item};
use super::report::{AreaReport, Item, Level};
use super::{Ctx, NET_TIMEOUT};
use crate::config::Config;
use crate::dns::provider::DnsProvider;
use crate::dns::{self, Check, Status};
use crate::spf::{DnsFailure, DnsLookup, SystemDns};

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// Check DNS with the system resolver.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	match SystemDns::from_system() {
		Ok(resolver) => evaluate(config, &TimeoutDns(resolver)).await,
		Err(error) => AreaReport::fail(format!("cannot start the resolver: {error}")),
	}
}

/// The check proper, against any resolver.
async fn evaluate(config: &Config, dns: &dyn DnsLookup) -> AreaReport {
	let mut findings = Vec::new();
	let keys = match signing_keys(config) {
		Ok(keys) => keys,
		Err(error) => {
			findings.push(Item::new("DKIM signing key", Level::Fail, error));
			Vec::new()
		}
	};
	let signing_key_failed = !findings.is_empty();
	findings.extend(state_item(config));
	// When the signing key cannot be resolved the failure is already
	// reported; the DNS records are still checked with whatever selectors
	// can be named, and with none if the rotation state itself is broken.
	let default_selectors: Vec<String> = if signing_key_failed {
		crate::cli::verify::dns::dkim_default_selectors(config).unwrap_or_default()
	} else {
		keys.iter()
			.filter(|k| k.domain.is_none())
			.map(|k| k.key.selector.clone())
			.collect()
	};

	let mut records = dns::check_host(
		&config.hostname,
		config.public_ipv4,
		config.public_ipv6,
		dns,
	)
	.await;
	for domain in &config.domains {
		// Each domain is checked against its own selectors: a per-domain
		// override replaces the default, otherwise the default applies.
		let selectors = crate::cli::verify::dns::dkim_selectors_for(config, domain)
			.unwrap_or_else(|_| default_selectors.clone());
		records.extend(dns::check_domain(domain, &config.hostname, &selectors, dns).await);
	}
	// Cloudflare's orange cloud breaks delivery to every mail name:
	// SMTP / IMAP / POP3 / submission all need direct traffic, and the
	// proxy only forwards HTTP(S). The check lives behind the configured
	// provider so other providers keep their existing surface.
	findings.extend(proxied_items(config, proxy_provider(config)).await);
	let mut items: Vec<Item> = records.iter().map(record_item).collect();
	let ok = count(&records, &Status::Ok);
	let missing = count(&records, &Status::Missing);
	let inconclusive = count(&records, &Status::LookupError);

	let mut mismatches = 0;
	for domain in &config.domains {
		// A domain with a `[[dkim.domain]]` override is checked against the
		// override's keys only, the default's against every other domain.
		let own = config
			.dkim
			.as_ref()
			.and_then(|dkim| dkim.override_for(domain))
			.map(|entry| entry.name.to_ascii_lowercase());
		for key in keys.iter().filter(|key| key.domain == own) {
			if let Some(item) = key_item(&key.key, domain, dns).await {
				mismatches += usize::from(item.status == Level::Fail);
				findings.push(item);
			}
		}
	}
	// A split that is not finished: the shared key is still published at a
	// domain that has a key of its own.
	let stale = match crate::dkim::stale::names(config) {
		Ok(candidates) => crate::dkim::stale::published(dns, candidates).await,
		Err(_) => Vec::new(),
	};
	for record in &stale {
		findings.push(Item::new(
			format!("DKIM split {}", record.name),
			Level::Warn,
			"split incomplete: the shared [dkim] key is still published here; `epistle dkim split --finish` retires it after the overlap",
		));
	}
	let mut summary = format!("{ok} records ok");
	for (count, what) in [
		(missing, "missing"),
		(inconclusive, "inconclusive"),
		(mismatches, "DKIM key mismatch"),
		(stale.len(), "shared DKIM key still published"),
		(
			usize::from(signing_key_failed),
			"DKIM signing key unreadable",
		),
	] {
		if count > 0 {
			summary.push_str(&format!(", {count} {what}"));
		}
	}
	items.extend(findings);
	AreaReport::from_items(items, summary)
}

fn count(records: &[Check], status: &Status) -> usize {
	records
		.iter()
		.filter(|check| &check.status == status)
		.count()
}

fn record_item(check: &Check) -> Item {
	let level = match check.status {
		Status::Ok => Level::Ok,
		Status::Missing => Level::Fail,
		Status::LookupError => Level::Warn,
	};
	Item::new(
		format!("{} {}", check.kind, check.name),
		level,
		check.detail.clone(),
	)
}

/// The DKIM comparison for one key at one domain; `None` when nothing is
/// published there (the plain record check already reports that) or the
/// lookup failed.
async fn key_item(key: &SigningKey, domain: &str, dns: &dyn DnsLookup) -> Option<Item> {
	let name = format!("{}._domainkey.{domain}", key.selector);
	let published = dns.txt(&name).await.ok()?;
	compare(key, domain, &published)
}

/// The provider the orange-cloud check reads: Cloudflare only. `Err`
/// when Cloudflare is configured but its credentials cannot be read.
fn proxy_provider(config: &Config) -> Result<Option<Arc<dyn DnsProvider>>, ()> {
	if !dns::proxied_check::proxy_aware_provider(config) {
		return Ok(None);
	}
	// An entry whose credentials cannot be read must not look like a zone
	// with no proxied names: the router would answer it as a manual zone.
	let unreadable = config
		.dns
		.iter()
		.filter(|dns| dns.provider.eq_ignore_ascii_case("cloudflare"))
		.any(|dns| dns.build_for_host(&config.hostname).is_none());
	if unreadable {
		return Err(());
	}
	config
		.dns
		.build_for_host(&config.hostname)
		.map(Some)
		.ok_or(())
}

/// The Cloudflare orange-cloud check: one `Fail` per proxied mail name, so
/// `epistle status` exits 1 until the operator sets them to DNS only. The
/// zones are the ones the Cloudflare `[dns]` entries name; a list that fails
/// or times out is a warning, because the proxy state is then unknown.
pub(super) async fn proxied_items(
	config: &Config,
	provider: Result<Option<Arc<dyn DnsProvider>>, ()>,
) -> Vec<Item> {
	const LABEL: &str = "Cloudflare proxy";
	let provider = match provider {
		Ok(Some(provider)) => provider,
		Ok(None) => return Vec::new(),
		Err(()) => {
			return vec![Item::new(
				LABEL,
				Level::Warn,
				"the Cloudflare credentials in [dns] could not be read; the proxy state was not checked",
			)];
		}
	};
	let mut items = Vec::new();
	for zone in config
		.dns
		.iter()
		.filter(|dns| dns.provider.eq_ignore_ascii_case("cloudflare"))
		.map(|dns| dns.zone.as_str())
	{
		items.extend(zone_items(config, provider.as_ref(), zone).await);
	}
	items
}

/// The orange-cloud findings of one Cloudflare zone.
async fn zone_items(config: &Config, provider: &dyn DnsProvider, zone: &str) -> Vec<Item> {
	const LABEL: &str = "Cloudflare proxy";
	let check =
		dns::proxied_check::proxied_check(provider, zone, &config.domains, &config.hostname);
	match tokio::time::timeout(NET_TIMEOUT, check).await {
		Ok(Ok(names)) => names
			.iter()
			.map(|name| {
				Item::new(
					format!("{LABEL} {name}"),
					Level::Fail,
					dns::proxied_check::proxied_message(name),
				)
			})
			.collect(),
		Ok(Err(error)) => vec![Item::new(
			LABEL,
			Level::Warn,
			format!("listing the {zone} zone failed, so the proxy state was not checked: {error}"),
		)],
		Err(_) => vec![Item::new(
			LABEL,
			Level::Warn,
			format!("listing the {zone} zone timed out, so the proxy state was not checked"),
		)],
	}
}

/// Wraps a resolver so no single query outlives [`NET_TIMEOUT`]. `init`
/// uses it for its reverse-DNS block too.
pub(crate) struct TimeoutDns<D>(pub(crate) D);

impl<D: DnsLookup> DnsLookup for TimeoutDns<D> {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let query = self.0.txt(name);
		Box::pin(async move { bounded(query).await })
	}
	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>> {
		let query = self.0.addresses(name);
		Box::pin(async move { bounded(query).await })
	}
	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let query = self.0.mx(name);
		Box::pin(async move { bounded(query).await })
	}
	fn ptr(&self, ip: IpAddr) -> Lookup<'_, Vec<String>> {
		let query = self.0.ptr(ip);
		Box::pin(async move { bounded(query).await })
	}
	fn tlsa(&self, name: &str) -> Lookup<'_, crate::dane::rrset::TlsaRrset> {
		let query = self.0.tlsa(name);
		Box::pin(async move { bounded(query).await })
	}
}

async fn bounded<T>(query: Lookup<'_, T>) -> Result<T, DnsFailure> {
	tokio::time::timeout(NET_TIMEOUT, query)
		.await
		.unwrap_or(Err(DnsFailure::Temporary))
}

#[cfg(test)]
mod tests;
