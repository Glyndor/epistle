//! Per-tenant limits: aggregate caps the operator sets on a group of domains
//! to make tenancy fit for resellers.
//!
//! A tenant is a named bag of domains with optional limits on accounts,
//! domains, aggregate storage and submission rate. With no `[[tenant]]` block
//! the server runs exactly as it always has — the empty list is the identity
//! the rest of the code branches against.
//!
//! A tenant limit is enforced on top of (never instead of) the per-domain and
//! per-account limits the rest of the config carries. When `quota_bytes` is
//! set, the sum of every configured `domain_quotas` entry that lands inside
//! the tenant must fit under it; anything else is a config error because the
//! cap would be unreachable.

use serde::Deserialize;

/// One tenant: a named collection of domains with optional aggregate limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
	/// Stable identifier for the tenant. Operators see it in error messages;
	/// it never appears in a network response.
	#[serde(default)]
	pub name: Option<String>,
	/// Domains that belong to this tenant. Every entry must also appear under
	/// the top-level `domains` list — a tenant cannot own a domain the
	/// server does not host.
	#[serde(default)]
	pub domains: Vec<String>,
	/// Aggregate storage cap (bytes) across every account in every domain of
	/// this tenant. Absent means no aggregate cap; the per-domain and
	/// per-account quotas still apply.
	#[serde(default)]
	pub quota_bytes: Option<u64>,
	/// Maximum number of accounts (static + dynamic) this tenant may hold.
	/// Absent means no cap.
	#[serde(default)]
	pub max_accounts: Option<u64>,
	/// Maximum number of domains this tenant may declare. Absent means no
	/// cap; the cap cannot be lower than `domains.len()` because that would
	/// make the tenant unloadable.
	#[serde(default)]
	pub max_domains: Option<u64>,
	/// Aggregate submission rate ceiling for the tenant (messages per minute,
	/// summed across every authenticated sender in every domain of the
	/// tenant). Sits on top of — not in place of — the global
	/// `submission_rate_limit_per_min` per-account limiter.
	#[serde(default)]
	pub submission_rate_limit_per_min: Option<u32>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_tenant_block() {
		let tenant: Tenant = toml::from_str(
			r#"
name = "acme"
domains = ["acme.example", "acme-mail.example"]
quota_bytes = 1073741824
max_accounts = 50
max_domains = 5
submission_rate_limit_per_min = 200
"#,
		)
		.expect("parse tenant");
		assert_eq!(tenant.name.as_deref(), Some("acme"));
		assert_eq!(tenant.domains.len(), 2);
		assert_eq!(tenant.quota_bytes, Some(1_073_741_824));
		assert_eq!(tenant.max_accounts, Some(50));
		assert_eq!(tenant.max_domains, Some(5));
		assert_eq!(tenant.submission_rate_limit_per_min, Some(200));
	}

	#[test]
	fn parses_minimal_tenant() {
		let tenant: Tenant = toml::from_str(
			r#"
domains = ["only.example"]
"#,
		)
		.expect("parse minimal tenant");
		assert_eq!(tenant.name, None);
		assert_eq!(tenant.domains, vec!["only.example".to_string()]);
		assert_eq!(tenant.quota_bytes, None);
		assert_eq!(tenant.max_accounts, None);
		assert_eq!(tenant.max_domains, None);
		assert_eq!(tenant.submission_rate_limit_per_min, None);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Tenant, _> = toml::from_str(
			r#"
domains = ["only.example"]
surprise = true
"#,
		);
		assert!(result.is_err());
	}
}
