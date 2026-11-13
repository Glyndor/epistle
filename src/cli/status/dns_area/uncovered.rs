//! Names under a hosted domain that carry no null SPF and null MX yet.
//!
//! The same decision `dns lockdown` and the reconcile loop make, read from
//! the zone through the configured provider. A name is covered when it has
//! the null records (written by epistle or not needed), is declared as
//! sending, or has records of its own.

use std::sync::Arc;

use super::super::NET_TIMEOUT;
use super::super::report::{Item, Level};
use crate::config::Config;
use crate::dns::lockdown::null_set;
use crate::dns::names::ServedNames;
use crate::dns::provider::DnsProvider;

const LABEL: &str = "Null records";

/// How many names the line names before it counts the rest.
const SHOWN: usize = 5;

/// The provider that lists the zones: the one `[dns]` configures, `None`
/// when no entry can read a zone (no `[dns]`, or `manual`).
pub(super) fn provider(config: &Config) -> Option<Arc<dyn DnsProvider>> {
	if config
		.dns
		.iter()
		.all(|entry| entry.provider.eq_ignore_ascii_case("manual"))
	{
		return None;
	}
	config.dns.build_for_host(&config.hostname)
}

/// One warning for the names of every hosted domain that are not covered,
/// and one for a zone that could not be read. Nothing without a provider.
pub(super) async fn items(config: &Config, provider: Option<Arc<dyn DnsProvider>>) -> Vec<Item> {
	let Some(provider) = provider else {
		return Vec::new();
	};
	let mut items = Vec::new();
	for domain in &config.domains {
		items.extend(domain_items(config, provider.as_ref(), domain).await);
	}
	items
}

async fn domain_items(config: &Config, provider: &dyn DnsProvider, domain: &str) -> Vec<Item> {
	let read = async {
		let zone = crate::dns::zone::resolve(provider, domain)
			.await
			.map_err(|error| error.to_string())?;
		let existing = provider
			.list(&zone)
			.await
			.map_err(|error| error.to_string())?;
		Ok::<_, String>((zone, existing))
	};
	let (zone, existing) = match tokio::time::timeout(NET_TIMEOUT, read).await {
		Ok(Ok(found)) => found,
		Ok(Err(why)) => {
			return vec![Item::new(
				format!("{LABEL} {domain}"),
				Level::Warn,
				format!("the zone could not be read, so the names were not checked: {why}"),
			)];
		}
		Err(_) => {
			return vec![Item::new(
				format!("{LABEL} {domain}"),
				Level::Warn,
				"reading the zone timed out, so the names were not checked",
			)];
		}
	};
	let mut ours = crate::dns::reconcile::store::load(&config.data_dir, &zone)
		.map(|ledger| ledger.records())
		.unwrap_or_default();
	ours.extend(crate::dns::reconcile::survey::lockdown_records(config, &zone).unwrap_or_default());
	let served = ServedNames::new(&config.domains, &config.hostname, &existing)
		.with_senders(&config.dns_publish.senders);
	let uncovered = null_set(
		&zone,
		&crate::dns::names::canonical_name(domain),
		&served,
		&existing,
		&ours,
	)
	.uncovered;
	if uncovered.is_empty() {
		return Vec::new();
	}
	let shown: Vec<&str> = uncovered.iter().take(SHOWN).map(String::as_str).collect();
	let more = uncovered.len().saturating_sub(shown.len());
	let tail = if more > 0 {
		format!(", +{more} more")
	} else {
		String::new()
	};
	let fix = if config.dns_publish.null_records {
		"the next reconcile run covers them"
	} else {
		"`epistle dns lockdown` covers them, or set [dns_publish] null_records"
	};
	vec![Item::new(
		format!("{LABEL} {domain}"),
		Level::Warn,
		format!(
			"{} names have no null SPF and null MX ({}{tail}); {fix}",
			uncovered.len(),
			shown.join(", ")
		),
	)]
}
