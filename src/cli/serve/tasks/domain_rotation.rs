//! The rotation of each domain's own DKIM key (`[[dkim.domain]]`), one task
//! per domain beside the rotation of the `[dkim]` key.
//!
//! A domain rotates when a `[dns]` entry can publish its records. A domain no
//! entry reaches keeps its key and is named in the log once; it does not
//! hold back the others, since each domain has its own state and records.

use std::sync::Arc;

use super::DnsWrite;
use crate::config::Config;

/// Which `[[dkim.domain]]` keys the server rotates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRotationPlan {
	/// Domains whose key rotates, lowercase, in the configuration's order.
	pub rotating: Vec<String>,
	/// Domains with a key of their own that no `[dns]` entry can publish
	/// for: their key does not rotate.
	pub unmanaged: Vec<String>,
}

/// Whether a `[dns]` entry can publish records at `domain`.
///
/// With `[[dns]]` entries the entry of the domain's own zone must be able
/// to publish (not `manual`, with a credential that loads); a lone `[dns]`
/// must hold the domain in its zone.
///
/// `holds_credential` says whether this process holds the credential at all.
/// With the certificates container on it does not: the credential is in the
/// other container, and asking this process for it would refuse every zone.
/// What the entry must be then is one that is not `manual`, because the
/// container that holds the credential refuses a manual zone too.
pub(in crate::cli) fn dns_publishes_for(
	config: &Config,
	domain: &str,
	holds_credential: bool,
) -> bool {
	if config.dns.scoped() {
		config.dns.entry_for(domain).is_some_and(|dns| {
			crate::dkim::Rotator::is_in_zone(domain, &dns.zone)
				&& if holds_credential {
					dns.build_for_host(&config.hostname).is_some()
				} else {
					!dns.provider.eq_ignore_ascii_case("manual")
				}
		})
	} else {
		config
			.dns
			.iter()
			.any(|dns| crate::dkim::Rotator::is_in_zone(domain, &dns.zone))
	}
}

/// Pure policy: which domains' own keys rotate.
pub fn decide_domain_rotation(config: &Config, write: &DnsWrite) -> DomainRotationPlan {
	let mut plan = DomainRotationPlan::default();
	let Some(dkim) = &config.dkim else {
		return plan;
	};
	for entry in &dkim.domain {
		let domain = entry.name.to_ascii_lowercase();
		if !config.dns.is_empty() && dns_publishes_for(config, &domain, write.holds_credential()) {
			plan.rotating.push(domain);
		} else {
			plan.unmanaged.push(domain);
		}
	}
	plan
}

/// Spawn one rotation task per domain whose key [`decide_domain_rotation`]
/// says rotates. `signers` are the live signers of the domains, the ones
/// the delivery sink signs with.
///
/// `write` says where the records go: the provider this process holds, or
/// the hand-off the certificates container serves.
pub fn spawn_domain_rotations(
	config: &Config,
	signers: &[crate::dkim::DomainSigner],
	webhook: Option<Arc<crate::webhook::Webhook>>,
	write: &DnsWrite,
) {
	let Some(dkim) = &config.dkim else {
		return;
	};
	let plan = decide_domain_rotation(config, write);
	if !plan.unmanaged.is_empty() {
		tracing::warn!(
			domains = ?plan.unmanaged,
			"the DKIM keys of these domains do not rotate: no [dns] entry can publish their records",
		);
	}
	if plan.rotating.is_empty() {
		return;
	}
	// One write at a time across every domain: a provider that rewrites a
	// whole record set could lose one of two concurrent changes.
	let writes = Arc::new(tokio::sync::Mutex::new(()));
	let provider = match write {
		DnsWrite::Direct => {
			let Some(provider) = config.dns.build_for_host(&config.hostname) else {
				tracing::warn!(
					"per-domain DKIM rotation is disabled: the [dns] provider cannot be built"
				);
				return;
			};
			// Built again at the start of every cycle of a rotation, so a
			// token file that changed is read again.
			Some(super::dns_reconcile::live_provider(config, provider))
		}
		DnsWrite::Handoff(_) => None,
	};
	// A new key signs only once a resolver sees it; without one nothing
	// rotates and every domain keeps the key it has.
	let resolver: Arc<dyn crate::spf::DnsLookup> = match crate::spf::SystemDns::uncached_from_system(
	) {
		Ok(resolver) => Arc::new(resolver),
		Err(error) => {
			tracing::warn!(%error, "per-domain DKIM rotation is disabled: no system resolver to confirm new keys in DNS");
			return;
		}
	};
	let mut reserved = dkim.kept_selectors();
	match crate::dkim::domain_keys::reserved_selectors(config) {
		Ok(selectors) => reserved.extend(selectors),
		Err(error) => {
			tracing::warn!(%error, "per-domain DKIM rotation is disabled: the [dkim] key's selectors cannot be read");
			return;
		}
	}
	for domain in plan.rotating {
		let (Some(entry), Some(signer)) = (
			dkim.override_for(&domain),
			signers
				.iter()
				.find(|s| s.domain.eq_ignore_ascii_case(&domain)),
		) else {
			continue;
		};
		let publisher: Arc<dyn crate::dkim::domain_rotate::KeyPublisher> =
			match (write, provider.as_ref()) {
				(DnsWrite::Direct, Some(provider)) => Arc::new(
					crate::dkim::domain_rotate::ProviderPublisher::live(
						Arc::clone(provider),
						config.dns.zones(),
					)
					.sharing_writes(Arc::clone(&writes)),
				),
				(DnsWrite::Handoff(dir), _) => Arc::new(
					crate::dkim::domain_rotate::HandoffPublisher::new(
						crate::dns::handoff::Writer::at(dir.clone()),
					)
					.sharing_writes(Arc::clone(&writes)),
				),
				// The provider is built before the loop, and the loop is not
				// reached without one.
				(DnsWrite::Direct, None) => continue,
			};

		let rotator = match crate::dkim::domain_rotate::DomainRotator::new(
			config.data_dir.clone(),
			entry.clone(),
			signer.signer.clone(),
			publisher,
			Arc::clone(&resolver),
			crate::dkim::publication_waits(),
		) {
			Ok(rotator) => rotator.reserving(reserved.clone()),
			Err(error) => {
				tracing::warn!(%domain, %error, "the DKIM key of the domain does not rotate");
				continue;
			}
		};
		let rotator = match &webhook {
			Some(webhook) => rotator.with_webhook(Arc::clone(webhook)),
			None => rotator,
		};
		tokio::spawn(run(rotator));
	}
}

/// Wake every minute so an operator's request is served promptly; the
/// scheduled tick runs every hour.
async fn run(rotator: crate::dkim::domain_rotate::DomainRotator) {
	let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
	let mut minutes: u64 = 0;
	loop {
		ticker.tick().await;
		let auto_due = minutes.is_multiple_of(60);
		minutes += 1;
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		if let Err(error) = rotator.cycle(now, auto_due).await {
			tracing::warn!(domain = %rotator.domain(), %error, "DKIM rotation tick of the domain failed");
		}
	}
}
