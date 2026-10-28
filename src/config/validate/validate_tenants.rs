//! Tenant config validation, split out of `validate.rs` to keep both files
//! under the per-file line limit.

use std::collections::{HashMap, HashSet};

use super::{Config, ConfigError};
use crate::config::Tenant;
use crate::config::validate_dns_name;

impl Config {
	pub(super) fn validate_tenants(&self) -> Result<(), ConfigError> {
		if self.tenants.is_empty() {
			return Ok(());
		}
		let configured_domains: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut names_seen: HashSet<String> = HashSet::new();
		// The first tenant to claim a domain wins; every subsequent claim is
		// rejected, naming both tenants in the message so the operator can
		// disambiguate without flipping back through the file.
		let mut domain_owner: HashMap<String, String> = HashMap::new();
		for tenant in &self.tenants {
			if let Some(name) = &tenant.name
				&& !names_seen.insert(name.clone())
			{
				return Err(ConfigError::Invalid(format!(
					"[[tenant]] name \"{name}\" is declared more than once"
				)));
			}
			if let Some(max) = tenant.max_domains
				&& (max as usize) < tenant.domains.len()
			{
				return Err(ConfigError::Invalid(format!(
					"[[tenant]] {} max_domains ({max}) is smaller than the number of domains declared ({})",
					tenant_label(tenant),
					tenant.domains.len()
				)));
			}
			let mut seen_in_tenant: HashSet<String> = HashSet::new();
			for raw in &tenant.domains {
				validate_dns_name("tenant domain", raw)?;
				let lc = raw.to_ascii_lowercase();
				if !configured_domains.contains(&lc) {
					return Err(ConfigError::Invalid(format!(
						"[[tenant]] {} domain \"{raw}\" is not a configured domain",
						tenant_label(tenant)
					)));
				}
				if !seen_in_tenant.insert(lc.clone())
					&& let Some(name) = &tenant.name
				{
					return Err(ConfigError::Invalid(format!(
						"[[tenant]] \"{name}\" declares domain \"{raw}\" more than once"
					)));
				}
				if let Some(other) = domain_owner.get(&lc) {
					return Err(ConfigError::Invalid(format!(
						"domain \"{raw}\" is claimed by both tenants \"{other}\" and \"{}\"",
						tenant_label(tenant)
					)));
				}
				domain_owner.insert(lc, tenant_label(tenant).to_string());
			}
			if let Some(tenant_quota) = tenant.quota_bytes {
				let mut sum: u64 = 0;
				for domain in &tenant.domains {
					if let Some(bytes) = self.domain_quotas.get(domain) {
						sum = sum.saturating_add(*bytes);
					}
				}
				if sum > tenant_quota {
					return Err(ConfigError::Invalid(format!(
						"[[tenant]] {} quota_bytes ({tenant_quota}) is below the sum of its domains' domain_quotas ({sum})",
						tenant_label(tenant)
					)));
				}
			}
		}
		Ok(())
	}
}

/// A short label for a tenant in error messages: the configured `name` if any,
/// else `"<unnamed tenant>"`. Two unnamed tenants sharing a domain would still
/// fail validation, but the message stays readable.
fn tenant_label(tenant: &Tenant) -> String {
	tenant
		.name
		.clone()
		.unwrap_or_else(|| "<unnamed tenant>".to_string())
}
