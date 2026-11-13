//! The null SPF and null MX of the hosted domains in a zone, as records the
//! reconcile loop keeps true like the rest of the needed set.
//!
//! They are not part of [`crate::dns::desired`]: which names need them
//! depends on what the zone holds, so they are computed here, against the
//! listing the run already took, with the decision `dns lockdown` makes.

use std::collections::BTreeSet;

use crate::config::Config;
use crate::dns::lockdown::{hosted_in_zone, in_domain, null_set};
use crate::dns::names::ServedNames;
use crate::dns::provider::DnsRecord;

/// The null records the hosted domains in `zone` need. With `scope`, only
/// the domains it contains or is inside. `ours` are the records epistle
/// published before. A record not returned here that `ours` holds no
/// longer applies.
pub(super) fn needed(
	config: &Config,
	zone: &str,
	scope: Option<&str>,
	existing: &[DnsRecord],
	ours: &[DnsRecord],
) -> Vec<DnsRecord> {
	let served = ServedNames::new(&config.domains, &config.hostname, existing)
		.with_senders(&config.dns_publish.senders);
	let mut seen = BTreeSet::new();
	let mut records = Vec::new();
	for domain in hosted_in_zone(&config.domains, zone) {
		if scope.is_some_and(|s| !in_domain(&domain, s) && !in_domain(s, &domain)) {
			continue;
		}
		for record in null_set(zone, &domain, &served, existing, ours).needed {
			let key = (
				record.name.clone(),
				record.kind.as_str().to_string(),
				record.value.clone(),
			);
			if seen.insert(key) {
				records.push(record);
			}
		}
	}
	records
}
