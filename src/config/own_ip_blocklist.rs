//! Configuration for periodic checks of the server's own public addresses.

use std::collections::HashSet;

use serde::Deserialize;

use super::ConfigError;

/// Default interval between own-address blocklist checks.
pub(crate) const DEFAULT_PERIOD_SECS: u64 = 3_600;

/// Shortest interval accepted for own-address blocklist checks.
pub(crate) const MIN_PERIOD_SECS: u64 = 300;

/// Most zones one check may query, so a period never turns into a flood of
/// lookups against public resolvers.
pub(crate) const MAX_ZONES: usize = 16;

/// Configuration for periodic DNS blocklist checks of the server's own addresses.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnIpBlocklist {
	/// Whether the periodic check runs.
	#[serde(default = "default_enabled")]
	pub enabled: bool,
	/// Zones queried for the server's own addresses. Empty inherits `dnsbl_zones`.
	#[serde(default)]
	pub zones: Vec<String>,
	/// Seconds between checks.
	#[serde(default = "default_period")]
	pub period_secs: u64,
}

impl Default for OwnIpBlocklist {
	fn default() -> Self {
		Self {
			enabled: true,
			zones: Vec::new(),
			period_secs: DEFAULT_PERIOD_SECS,
		}
	}
}

impl OwnIpBlocklist {
	pub(crate) fn effective_zones(&self, inherited: &[String]) -> Vec<String> {
		let source = if self.zones.is_empty() {
			inherited
		} else {
			&self.zones
		};
		let mut seen = HashSet::new();
		source
			.iter()
			.map(|zone| normalize_zone(zone))
			.filter(|zone| !zone.is_empty())
			.filter(|zone| seen.insert(zone.clone()))
			.collect()
	}

	pub(crate) fn validate(&self, inherited: &[String]) -> Result<(), ConfigError> {
		if self.period_secs < MIN_PERIOD_SECS {
			return Err(ConfigError::Invalid(format!(
				"[own_ip_blocklist] period_secs must be at least {MIN_PERIOD_SECS} seconds"
			)));
		}
		let source = if self.zones.is_empty() {
			inherited
		} else {
			&self.zones
		};
		if self.effective_zones(inherited).len() > MAX_ZONES {
			return Err(ConfigError::Invalid(format!(
				"[own_ip_blocklist] at most {MAX_ZONES} zones may be checked"
			)));
		}
		for zone in source {
			let trimmed = zone.trim();
			if trimmed.is_empty() {
				return Err(ConfigError::Invalid(
					"[own_ip_blocklist] zones must not contain an empty zone".into(),
				));
			}
			if !trimmed.contains('.') {
				return Err(ConfigError::Invalid(format!(
					"[own_ip_blocklist] zone {trimmed:?} must be a fully qualified DNS name"
				)));
			}
			super::validate_dns_name("own_ip_blocklist zone", trimmed)?;
		}
		Ok(())
	}
}

impl super::Config {
	pub(crate) fn own_ip_blocklist_zones(&self) -> Vec<String> {
		self.own_ip_blocklist.effective_zones(&self.dnsbl_zones)
	}
}

fn default_enabled() -> bool {
	true
}

fn default_period() -> u64 {
	DEFAULT_PERIOD_SECS
}

fn normalize_zone(zone: &str) -> String {
	zone.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn zones(names: &[&str]) -> Vec<String> {
		names.iter().map(|name| name.to_string()).collect()
	}

	#[test]
	fn the_check_is_on_by_default_with_an_hourly_period() {
		let config: OwnIpBlocklist = toml::from_str("").expect("parses");
		assert!(config.enabled);
		assert_eq!(config.period_secs, 3_600);
		assert!(config.zones.is_empty());
	}

	#[test]
	fn empty_zones_inherit_the_inbound_ones_and_own_zones_replace_them() {
		let inherited = zones(&["Zen.Spamhaus.org.", "bl.example", "bl.example"]);
		let config = OwnIpBlocklist::default();
		assert_eq!(
			config.effective_zones(&inherited),
			zones(&["zen.spamhaus.org", "bl.example"])
		);
		let own = OwnIpBlocklist {
			zones: zones(&["only.example"]),
			..OwnIpBlocklist::default()
		};
		assert_eq!(own.effective_zones(&inherited), zones(&["only.example"]));
	}

	#[test]
	fn a_period_under_the_minimum_is_refused() {
		let config = OwnIpBlocklist {
			period_secs: MIN_PERIOD_SECS - 1,
			..OwnIpBlocklist::default()
		};
		let error = config.validate(&[]).expect_err("too short");
		assert!(error.to_string().contains("period_secs"), "{error}");
		let ok = OwnIpBlocklist {
			period_secs: MIN_PERIOD_SECS,
			..OwnIpBlocklist::default()
		};
		assert!(ok.validate(&[]).is_ok());
	}

	#[test]
	fn a_bad_zone_is_refused() {
		for bad in ["", "  ", "nodots", "bad zone.example"] {
			let config = OwnIpBlocklist {
				zones: zones(&[bad]),
				..OwnIpBlocklist::default()
			};
			assert!(config.validate(&[]).is_err(), "{bad:?}");
		}
	}

	#[test]
	fn an_inherited_bad_zone_is_refused_too() {
		assert!(
			OwnIpBlocklist::default()
				.validate(&zones(&["nodots"]))
				.is_err()
		);
	}

	#[test]
	fn too_many_zones_are_refused() {
		let many: Vec<String> = (0..=MAX_ZONES).map(|n| format!("z{n}.example")).collect();
		let config = OwnIpBlocklist {
			zones: many,
			..OwnIpBlocklist::default()
		};
		assert!(config.validate(&[]).is_err());
	}

	#[test]
	fn an_unknown_key_is_refused() {
		assert!(toml::from_str::<OwnIpBlocklist>("period = 5").is_err());
	}

	#[test]
	fn the_full_config_validates_the_section() {
		let body = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[own_ip_blocklist]\nperiod_secs = 10\n";
		let config: crate::config::Config = toml::from_str(body).expect("parses");
		assert!(config.validate().is_err());
	}
}
