//! API state views.

use super::*;

impl ApiState {
	/// Attach the per-tenant aggregate limits. Must be set before the state
	/// is shared (it rebuilds the `Arc` inner). With no configured tenants
	/// the runtime is the identity, every check returns "no cap". The
	/// `Arc` lets the SMTP server share the same instance without a clone.
	pub fn with_tenant_limits(mut self, limits: Arc<TenantLimits>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.tenant_limits = (*limits).clone();
		}
		self
	}

	/// Attach the per-account correspondent store. Must be set before
	/// the state is shared (it rebuilds the `Arc` inner). Required for
	/// the rolling 24h new-recipient cap (`POST /api/v1/send`, JMAP
	/// `EmailSubmission/set`); unset handlers fall through to the
	/// pre-feature behaviour rather than silently skipping the cap.
	pub fn with_correspondents(mut self, store: crate::storage::CorrespondentStore) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.correspondents = Some(store);
		}
		self
	}

	/// The per-account correspondent store when one has been attached.
	/// `None` means the cap cannot be enforced; handlers fall through
	/// to the pre-feature behaviour instead.
	pub fn correspondents(&self) -> Option<&crate::storage::CorrespondentStore> {
		self.inner.correspondents.as_ref()
	}

	/// Set the rolling 24h cap on first-time recipients per account
	/// (`Config::new_recipients_per_day`). Must be set before the state
	/// is shared (it rebuilds the `Arc` inner). `None` disables the cap.
	pub fn with_new_recipients_per_day(mut self, limit: Option<u32>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.new_recipients_per_day = limit;
		}
		self
	}

	/// The configured daily new-recipient cap, when one is in effect.
	/// `None` means the cap is disabled; every submission is allowed.
	pub fn new_recipients_per_day(&self) -> Option<u32> {
		self.inner.new_recipients_per_day
	}

	/// The per-tenant aggregate limits. Empty when no `[[tenant]]` is
	/// configured; the empty state short-circuits every check to "no cap",
	/// which is the pre-tenancy behaviour bit-for-bit.
	pub fn tenant_limits(&self) -> &TenantLimits {
		&self.inner.tenant_limits
	}

	/// Shared handle for wiring the same limits into the SMTP server. Kept
	/// separate from `tenant_limits()` so callers do not need to construct
	/// an `Arc` themselves just to mirror the state.
	pub fn tenant_limits_handle(&self) -> Arc<TenantLimits> {
		Arc::new(self.inner.tenant_limits.clone())
	}

	/// The quota in force for `account` (its own, its domain's, else the
	/// server default); `None` is no limit. The rule IMAP QUOTA applies.
	pub(crate) fn quota_for_account(&self, account: &str) -> Option<u64> {
		match self.directory_snapshot() {
			Some(directory) => {
				crate::smtp::quota::limit_for(&directory, account, self.quota_limit())
			}
			None => Some(self.quota_limit()).filter(|bytes| *bytes != 0),
		}
	}

	/// The server default per-account storage quota in bytes (0 = unlimited).
	pub fn quota_limit(&self) -> u64 {
		self.inner
			.quota_limit
			.load(std::sync::atomic::Ordering::Relaxed)
	}

	/// The mail domains this server hosts, as configured at startup. Used by
	/// the API to accept or reject account and domain operations.
	pub fn domains(&self) -> &[String] {
		&self.inner.domains
	}

	/// A snapshot of every account in the directory, with its delivery
	/// addresses and whether its mailbox is dynamic (provisioned on first
	/// delivery rather than declared up front).
	pub fn accounts(&self) -> Vec<AccountView> {
		self.inner
			.store
			.account_views()
			.into_iter()
			.map(|(name, addresses, dynamic)| AccountView {
				display_name: self.inner.store.display_name(&name),
				name,
				addresses,
				dynamic,
			})
			.collect()
	}

	/// The account directory this state was built over. Exposed for handlers
	/// that need operations not exposed on `State` itself (for example
	/// password changes or alias rewrites).
	pub fn store(&self) -> &AccountStore {
		&self.inner.store
	}

	/// Shared handle to the masked-address store. Handlers call
	/// [`crate::directory_store::MaskedAddressStore::add`] / `remove` /
	/// `set_enabled` directly; the store persists on each call and rebuilds
	/// the directory on the way back so the next resolution cycle sees the
	/// change.
	pub fn masked_handle(&self) -> std::sync::Arc<std::sync::RwLock<MaskedAddressStore>> {
		self.inner.store.masked_handle()
	}

	/// The on-disk spool where accepted messages land before queueing.
	pub fn spool(&self) -> &FsSpool {
		&self.inner.spool
	}

	/// The server's data directory: root for the spool, key material, and
	/// other persistent state.
	pub fn data_dir(&self) -> &std::path::Path {
		&self.inner.data_dir
	}

	/// Run `f` against the mutable PushSubscription store, returning its result.
	/// Used by `PushSubscription/get` and `/set`, which filter by caller.
	pub(crate) fn with_push_subscriptions<R>(
		&self,
		f: impl FnOnce(&mut Vec<crate::api::jmap::push_subscription::StoredSubscription>) -> R,
	) -> R {
		let mut guard = self
			.inner
			.push_subscriptions
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		f(&mut guard)
	}

	/// The per-caller counts of JMAP work in flight
	/// ([`crate::api::jmap::caller_slots`]).
	pub(crate) fn caller_slots(
		&self,
	) -> Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> {
		Arc::clone(&self.inner.caller_slots)
	}
}
