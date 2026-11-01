//! Which domain `dns lockdown` works on, and in which zone.
//!
//! With one `[dns]` entry the zone is that entry's. With several `[[dns]]`
//! entries it is the zone of the entry that holds the domain, and the
//! credential used is that entry's alone.

use crate::config::Config;
use crate::dns::lockdown::{self, canonical_name};

/// The domain, the zone that holds it, and whether that zone is left to the
/// operator (its entry is `manual` while other zones publish).
pub(super) struct Target {
	pub(super) domain: String,
	pub(super) zone: String,
	pub(super) manual_zone: bool,
}

/// Settle the target from the `DOMAIN` argument and the configuration. Every
/// refusal happens before anything is read from or written to a zone.
pub(super) fn settle(config: &Config, requested: Option<&str>) -> Result<Target, String> {
	// With no domain given the first configured zone is locked down.
	let first_zone = config.dns.first().map(|dns| canonical_name(&dns.zone));
	let domain = match requested {
		Some(raw) => crate::domain::normalize(raw.trim().trim_end_matches('.'))
			.map_err(|_| format!("{raw} is not a valid domain name"))?,
		None => first_zone
			.or_else(|| config.domains.first().map(|d| canonical_name(d)))
			.ok_or(
				"no domain given and none configured; name one: epistle dns lockdown <DOMAIN>",
			)?,
	};
	let entry = config.dns.entry_for(&domain);
	let zone = entry.map(|dns| canonical_name(&dns.zone));
	if let Some(zone) = &zone
		&& !lockdown::in_domain(&domain, zone)
	{
		return Err(format!(
			"{domain} is not in the {zone} zone the [dns] provider manages"
		));
	}
	let several = config.dns.len() > 1;
	if several && entry.is_none() {
		return Err(format!(
			"{domain} is not in the zone of any [[dns]] entry: {}",
			config.dns.zones().join(", ")
		));
	}
	let manual_zone =
		several && entry.is_some_and(|dns| dns.provider.eq_ignore_ascii_case("manual"));
	if let Some(entry) = entry
		&& several
		&& !manual_zone
		&& entry.build_for_host(&config.hostname).is_none()
	{
		return Err(format!(
			"the {} credentials of the [[dns]] entry for {} could not be read; check that the token file or environment variable is available to this user",
			entry.provider, entry.zone
		));
	}
	Ok(Target {
		zone: zone.unwrap_or_else(|| domain.clone()),
		domain,
		manual_zone,
	})
}
