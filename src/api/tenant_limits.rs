//! Per-tenant runtime limits.
//!
//! The static `[[tenant]]` block defines the rules; this module holds the
//! runtime state that backs them. An empty `tenants` config is the identity:
//! every helper short-circuits to "no cap" and the server behaves exactly as
//! it did before tenancy was wired in.
//!
//! Three things are enforced:
//!
//! - **`max_accounts`**: an account whose addresses land in a tenant is
//!   counted against that tenant's account cap. Crossing the cap returns
//!   `409 Conflict` — waiting will not lift it, the cap lifts when an account
//!   is deleted or an operator raises it.
//! - **`quota_bytes`**: aggregate storage across every account in every
//!   domain of the tenant. Enforced on JMAP upload, alongside the per-account
//!   quota. The aggregate is computed from `account_usage_bytes` per account
//!   in the tenant's domains.
//! - **`submission_rate_limit_per_min`**: aggregate submission rate, on top
//!   of the existing per-account limiter. Both must pass.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::api::jmap;
use crate::config::Tenant;
use crate::directory_store::AccountStore;
use crate::smtp::ratelimit::SendLimiter;
use crate::storage::MessageCrypto;

/// The runtime view of one tenant: the static limits plus a per-tenant
/// aggregate submission limiter shared across every SMTP listener and the
/// built-in OAuth submission path.
#[derive(Clone, Debug)]
pub struct TenantRuntime {
	/// The configured limit values (immutable after startup).
	pub config: Tenant,
	/// Aggregate submission limiter, present only when
	/// `submission_rate_limit_per_min` is configured.
	pub send_limiter: Option<Arc<SendLimiter>>,
	/// The tenant's domains, lowercased, for fast lookup.
	domains_lc: HashSet<String>,
}

impl TenantRuntime {
	/// Build the runtime from the static config.
	fn from_config(config: Tenant) -> Self {
		let domains_lc = config
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		// `SendLimiter` takes the ceiling per check rather than at
		// construction since the per-domain limits landed, so the tenant's
		// number travels to `check` instead of into `new`.
		let send_limiter = config
			.submission_rate_limit_per_min
			.map(|_| Arc::new(SendLimiter::new(60)));
		TenantRuntime {
			config,
			send_limiter,
			domains_lc,
		}
	}

	/// Whether `domain` (any case) is one of this tenant's domains.
	fn owns_domain(&self, domain: &str) -> bool {
		self.domains_lc.contains(&domain.to_ascii_lowercase())
	}

	/// The tenant's display name (configured `name`, or `<unnamed>`).
	fn label(&self) -> String {
		self.config
			.name
			.clone()
			.unwrap_or_else(|| "<unnamed tenant>".to_string())
	}
}

/// The aggregate tenant state shared with every API handler and the SMTP
/// submission path. With no configured tenants it is a no-op: every check
/// returns `Ok` because the search map is empty.
#[derive(Default, Clone, Debug)]
pub struct TenantLimits {
	/// One entry per `[[tenant]]`. The order mirrors the config file, which
	/// matters only for deterministic error messages.
	tenants: Vec<TenantRuntime>,
	/// Reverse index: domain (lowercased) → position in `tenants`.
	by_domain: HashMap<String, usize>,
}

impl TenantLimits {
	/// Build the runtime from the static config. An empty `tenants` slice
	/// produces the identity `TenantLimits`, which short-circuits every check
	/// to "no cap" — the pre-tenancy behaviour is preserved bit for bit.
	pub fn from_config(tenants: &[Tenant]) -> Self {
		if tenants.is_empty() {
			return TenantLimits::default();
		}
		let runtimes: Vec<TenantRuntime> = tenants
			.iter()
			.cloned()
			.map(TenantRuntime::from_config)
			.collect();
		let mut by_domain: HashMap<String, usize> = HashMap::new();
		for (index, runtime) in runtimes.iter().enumerate() {
			for domain in &runtime.domains_lc {
				by_domain.insert(domain.clone(), index);
			}
		}
		TenantLimits {
			tenants: runtimes,
			by_domain,
		}
	}

	/// Whether any tenant limits are configured. Cheap; lets call sites skip
	/// work without holding the aggregate locks.
	pub fn is_empty(&self) -> bool {
		self.tenants.is_empty()
	}

	/// All configured tenants, in config-file order.
	pub fn tenants(&self) -> &[TenantRuntime] {
		&self.tenants
	}

	/// Every tenant that owns at least one of `addresses`, in config order.
	/// Used by quota and rate-limit paths: an account straddling two tenants
	/// counts against both, matching the existing all-vs-any rule for scope
	/// (`src/api/domain_scope.rs`).
	fn tenants_for_addresses<'a, I>(&'a self, addresses: I) -> Vec<&'a TenantRuntime>
	where
		I: IntoIterator<Item = &'a str>,
	{
		let mut seen: HashSet<usize> = HashSet::new();
		let mut result = Vec::new();
		for raw in addresses {
			let Some((_, domain)) = raw.rsplit_once('@') else {
				continue;
			};
			if let Some(index) = self.by_domain.get(&domain.to_ascii_lowercase())
				&& seen.insert(*index)
			{
				result.push(&self.tenants[*index]);
			}
		}
		result
	}

	/// Count accounts whose addresses touch the tenant's domains. A static or
	/// dynamic account counts as one regardless of how many of its addresses
	/// land in the tenant.
	pub fn tenant_account_count(&self, tenant_index: usize, store: &AccountStore) -> u64 {
		let tenant = &self.tenants[tenant_index];
		let views = store.account_views();
		views
			.into_iter()
			.filter(|(_, addresses, _)| {
				addresses.iter().any(|raw| {
					raw.rsplit_once('@')
						.is_some_and(|(_, domain)| tenant.owns_domain(domain))
				})
			})
			.count() as u64
	}

	/// Reject the creation of a new account whose addresses touch a tenant
	/// that has already reached its `max_accounts` cap. Returns the tenant
	/// label of the first tenant at its cap; `Ok(())` when every tenant the
	/// account touches is still under its cap (or no tenant owns the
	/// account's domains).
	pub fn check_account_creation(
		&self,
		store: &AccountStore,
		addresses: &[String],
	) -> Result<(), String> {
		for tenant in self.tenants_for_addresses(addresses.iter().map(String::as_str)) {
			let Some(cap) = tenant.config.max_accounts else {
				continue;
			};
			// +1 because the candidate itself is not yet in the store.
			let projected =
				self.tenant_account_count(tenant_index_of(&self.tenants, tenant), store) + 1;
			if projected > cap {
				return Err(format!(
					"tenant \"{}\" has reached its max_accounts cap of {cap}",
					tenant.label()
				));
			}
		}
		Ok(())
	}

	/// The aggregate storage used (bytes) by every account whose addresses
	/// touch `tenant_index`. Each account is counted once even if multiple
	/// of its addresses are in the tenant.
	pub fn tenant_usage_bytes(
		&self,
		tenant_index: usize,
		store: &AccountStore,
		data_dir: &std::path::Path,
		crypto: &MessageCrypto,
	) -> u64 {
		let tenant = &self.tenants[tenant_index];
		let mut total: u64 = 0;
		let mut counted: HashSet<String> = HashSet::new();
		for (name, addresses, _) in store.account_views() {
			if !addresses.iter().any(|raw| {
				raw.rsplit_once('@')
					.is_some_and(|(_, domain)| tenant.owns_domain(domain))
			}) {
				continue;
			}
			if !counted.insert(name.clone()) {
				continue;
			}
			total = total.saturating_add(jmap::account_usage_bytes(data_dir, &name, crypto));
		}
		total
	}

	/// Reject an upload that would push the tenant (if any) owning
	/// `account_addresses` over its `quota_bytes`. `additional` is the size
	/// in bytes of the upload about to be stored.
	///
	/// Returns `Ok(())` when no tenant owns any of the addresses, or every
	/// tenant is still under its cap after the upload.
	pub fn check_aggregate_quota(
		&self,
		store: &AccountStore,
		data_dir: &std::path::Path,
		crypto: &MessageCrypto,
		account_addresses: &[String],
		additional: u64,
	) -> Result<(), String> {
		for tenant in self.tenants_for_addresses(account_addresses.iter().map(String::as_str)) {
			let Some(cap) = tenant.config.quota_bytes else {
				continue;
			};
			let index = tenant_index_of(&self.tenants, tenant);
			let usage = self.tenant_usage_bytes(index, store, data_dir, crypto);
			if usage.saturating_add(additional) > cap {
				return Err(format!(
					"tenant \"{}\" has reached its aggregate storage cap of {cap} bytes",
					tenant.label()
				));
			}
		}
		Ok(())
	}

	/// Every per-tenant aggregate submission limiter, in config order. Empty
	/// when no tenant configures a rate limit; the SMTP and OAuth paths
	/// check each one in turn.
	pub fn aggregate_send_limiters(&self) -> impl Iterator<Item = &Arc<SendLimiter>> {
		self.tenants
			.iter()
			.filter_map(|tenant| tenant.send_limiter.as_ref())
	}

	/// Whether a submission by an account whose addresses are
	/// `account_addresses` is over any per-tenant aggregate rate limit.
	/// The first tenant to reject wins; `Ok(())` when every tenant is under
	/// its cap or no tenant owns any address.
	///
	/// The configured limiter is consulted first so the rejection code path
	/// is exercised on a denied send; tests use this to drive both branches.
	pub fn check_aggregate_rate(
		&self,
		account_addresses: &[String],
		now: u64,
	) -> Result<(), String> {
		for tenant in self.tenants_for_addresses(account_addresses.iter().map(String::as_str)) {
			let Some(limiter) = &tenant.send_limiter else {
				continue;
			};
			// A single submission adds one to the count for every tenant
			// the account belongs to. The key is the tenant's own label so
			// every tenant tracks its own aggregate independently.
			let Some(per_min) = tenant.config.submission_rate_limit_per_min else {
				return Ok(());
			};
			if !limiter.check(&tenant.label(), per_min, now) {
				return Err(format!(
					"tenant \"{}\" submission rate limit exceeded",
					tenant.label()
				));
			}
		}
		Ok(())
	}
}

/// Index lookup helper: `tenants_for_addresses` returns borrowed references
/// that cannot carry their own index, so the public helpers recover it here.
fn tenant_index_of(tenants: &[TenantRuntime], target: &TenantRuntime) -> usize {
	// Pointer identity is enough — the slice never reorders after `from_config`.
	for (index, candidate) in tenants.iter().enumerate() {
		if std::ptr::eq(candidate as *const _, target as *const _) {
			return index;
		}
	}
	0
}

#[cfg(test)]
#[path = "tenant_limits_tests.rs"]
mod tests;
