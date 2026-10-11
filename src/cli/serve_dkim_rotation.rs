//! DKIM key-rotation policy and the background task that runs it.
//!
//! Pulled out of `serve_tasks` so the per-task spawners stay close to the
//! duties they own. The pure decision lives here next to the spawner that
//! consumes it so the two cannot drift apart on what "should we rotate" means.

use crate::config::Config;

/// Outcome of the pure rotation-decision policy. Returned by
/// [`decide_dkim_rotation`] so the decision is unit-testable without
/// spawning tokio tasks; [`spawn_dkim_rotation`] consumes it to log and
/// (when `Run`) actually spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimRotationPlan {
	/// Rotation will be spawned with the given timing (seconds) and the
	/// deprecated config fields were ignored.
	Run {
		/// Seconds between automatic rotations.
		interval: u64,
		/// Seconds the previous selector's TXT stays published after a
		/// rotation.
		overlap: u64,
		/// Whether the config still carried the now-ignored
		/// `rotate_days` / `rotate_overlap_days` fields, so a one-shot
		/// deprecation warning should be logged at startup.
		deprecated_fields_present: bool,
		/// Every configured signing domain that sits inside the DNS zone
		/// (the apex or a subdomain of it). Empty when the operator has no
		/// `[domains]` or every configured domain is outside the zone; the
		/// caller logs a clear warning and skips rotation in that case.
		signing_domains: Vec<String>,
		/// Configured signing domains that are outside the DNS zone. Used by
		/// the warning text so the operator can see exactly which entries
		/// block rotation; kept alongside `signing_domains` so the
		/// decision is reproducible without re-reading the config.
		out_of_zone: Vec<String>,
	},
	/// Rotation will not run. The caller logs the reason once so the
	/// operator is not left guessing.
	Off,
}

/// Pure policy: should the DKIM rotation task be spawned, with what timing,
/// and did the operator still set the now-ignored legacy fields? Pulled out
/// of [`spawn_dkim_rotation`] so it can be exercised without I/O.
pub fn decide_dkim_rotation(config: &Config) -> DkimRotationPlan {
	let Some(dkim) = &config.dkim else {
		return DkimRotationPlan::Off;
	};
	let deprecated = dkim.rotate_days.is_some() || dkim.rotate_overlap_days.is_some();
	let Some(dns) = &config.dns else {
		return DkimRotationPlan::Off;
	};
	let mut all = std::collections::BTreeSet::new();
	for domain in &config.domains {
		all.insert(domain.to_ascii_lowercase());
	}
	for key in config.domain_aliases.keys() {
		all.insert(key.to_ascii_lowercase());
	}
	let mut signing_domains = Vec::new();
	let mut out_of_zone = Vec::new();
	for domain in all {
		if crate::dkim::Rotator::is_in_zone(&domain, &dns.zone) {
			signing_domains.push(domain);
		} else {
			out_of_zone.push(domain);
		}
	}
	DkimRotationPlan::Run {
		interval: crate::dkim::ROTATE_INTERVAL_DAYS * 86_400,
		overlap: crate::dkim::ROTATE_OVERLAP_DAYS * 86_400,
		deprecated_fields_present: deprecated,
		signing_domains,
		out_of_zone,
	}
}

/// Spawn the automatic DKIM key-rotation task whenever `[dkim]` and `[dns]`
/// are both configured. Rotation is a security property of the server, so
/// it runs by default with the constant interval / overlap from
/// [`crate::dkim`]; an operator does not opt in.
///
/// The legacy `rotate_days` / `rotate_overlap_days` fields on `[dkim]` are
/// kept for backward compatibility (so existing configs keep loading under
/// `deny_unknown_fields`) but are ignored: a one-shot deprecation warning
/// is logged at startup when they appear. They will be removed in a future
/// release.
///
/// When `[dns]` is absent, rotation cannot publish the new selector's TXT
/// and so is not started, but the inactivity is logged once at startup
/// rather than left silent.
pub fn spawn_dkim_rotation(config: &Config, dkim_signer: &Option<crate::dkim::ReloadableSigner>) {
	match decide_dkim_rotation(config) {
		DkimRotationPlan::Off => {
			// Only the "no [dns]" case is interesting to log here: rotation
			// is a security property and the operator may have intended to
			// enable it. Other "off" cases (no [dkim], no signer) are
			// intentional and already visible from the surrounding config.
			if config.dkim.is_some() && config.dns.is_none() {
				tracing::info!(
					"[dkim] rotation is inactive: no [dns] provider is configured; \
                     DKIM keys will not rotate automatically"
				);
			}
		}
		DkimRotationPlan::Run {
			interval,
			overlap,
			deprecated_fields_present,
			signing_domains,
			out_of_zone,
		} => {
			if deprecated_fields_present {
				tracing::warn!(
					interval_days = crate::dkim::ROTATE_INTERVAL_DAYS,
					overlap_days = crate::dkim::ROTATE_OVERLAP_DAYS,
					"[dkim] rotate_days and rotate_overlap_days are deprecated and ignored; \
                     rotation runs automatically every {} days with a {} day overlap",
					crate::dkim::ROTATE_INTERVAL_DAYS,
					crate::dkim::ROTATE_OVERLAP_DAYS,
				);
			}
			// If any configured signing domain sits outside the managed
			// zone, rotation cannot keep its published records in sync.
			// Log the offenders, leave the signer's key material alone, and
			// skip rotation entirely: the operator must move the
			// misconfigured domain under the managed zone (or remove it)
			// for rotation to resume. Checked before the signer/provider
			// gates so a startup-time warning still fires even when those
			// gates would also refuse to spawn.
			if !out_of_zone.is_empty() {
				let zone = config
					.dns
					.as_ref()
					.map(|dns| dns.zone.as_str())
					.unwrap_or("");
				tracing::warn!(
					out_of_zone = ?out_of_zone,
					zone = %zone,
					"[dkim] rotation is disabled: domain(s) above lie outside the [dns] zone; \
					 automatic DKIM rotation cannot keep their TXT records in sync. \
					 Move the domain(s) under the managed zone or remove them from [domains] \
					 and [domain_aliases] to re-enable rotation",
				);
				return;
			}
			// The decision says "Run" because [dns] is present; build the
			// actual provider now. A missing or wrong [dns] falls through
			// to the same "silent off" as before, that is a separate
			// misconfiguration the operator must fix anyway (the DNS
			// provider is also used elsewhere, e.g. ACME TLSA).
			let Some(signer) = dkim_signer else {
				return;
			};
			let Some(dns) = config.dns.as_ref() else {
				return;
			};
			let Some(provider) = dns.build() else {
				return;
			};
			let zone = dns.zone.clone();
			let rotator = crate::dkim::Rotator::new(
				config.data_dir.clone(),
				signer.clone(),
				provider,
				zone.clone(),
				signing_domains,
				interval,
				overlap,
			);
			tokio::spawn(async move {
				let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
				loop {
					ticker.tick().await;
					let now = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0);
					if let Err(error) = rotator.tick(now).await {
						tracing::warn!(%error, "dkim rotation tick failed");
					}
				}
			});
		}
	}
}
