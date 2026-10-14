//! The `dns` check: published records against what epistle expects, reusing
//! the `verify-dns` checks, plus the DKIM public key against the key the
//! server actually signs with.

use std::net::IpAddr;

use super::dns_dkim::{SigningKey, compare, signing_keys, state_item};
use super::report::{AreaReport, Item, Level};
use super::{Ctx, NET_TIMEOUT};
use crate::config::Config;
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
	let selectors: Vec<String> = if signing_key_failed {
		crate::cli::verify_dns::dkim_selectors(config).unwrap_or_default()
	} else {
		keys.iter().map(|key| key.selector.clone()).collect()
	};

	let mut records = dns::check_host(
		&config.hostname,
		config.public_ipv4,
		config.public_ipv6,
		dns,
	)
	.await;
	for domain in &config.domains {
		records.extend(dns::check_domain(domain, &config.hostname, &selectors, dns).await);
	}
	let mut items: Vec<Item> = records.iter().map(record_item).collect();
	let ok = count(&records, &Status::Ok);
	let missing = count(&records, &Status::Missing);
	let inconclusive = count(&records, &Status::LookupError);

	let mut mismatches = 0;
	for domain in &config.domains {
		for key in &keys {
			if let Some(item) = key_item(key, domain, dns).await {
				mismatches += usize::from(item.status == Level::Fail);
				findings.push(item);
			}
		}
	}
	let mut summary = format!("{ok} records ok");
	for (count, what) in [
		(missing, "missing"),
		(inconclusive, "inconclusive"),
		(mismatches, "DKIM key mismatch"),
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
#[path = "dns_area_tests.rs"]
mod tests;
