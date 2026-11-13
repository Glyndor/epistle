//! A provider built again from the configuration at the start of every cycle
//! of the task that writes through it.
//!
//! A token read from a file or from the configuration can change while the
//! server runs, so a task that writes DNS records (the reconcile loop, the
//! DKIM rotations, the ACME renewal and its TLSA record) builds its provider
//! once per cycle from a source instead of keeping the one it started with.
//! A token read from an environment variable is the one of the process and
//! only changes with a restart.
//!
//! [`LiveProvider`] is itself a [`DnsProvider`]: every call goes to the
//! provider of the current cycle, so the code that writes does not change.

use std::sync::{Arc, Mutex, PoisonError};

use super::{DnsProvider, DnsRecord, ListOp, Op, ZoneOp};
use crate::dns::publish::provider::{Change, OperationOp, ReceiptOp, SnapshotOp};

/// Builds the provider from the configuration as it is now. The error says
/// what is missing and never carries the credential.
pub type ProviderSource = Arc<dyn Fn() -> Result<Arc<dyn DnsProvider>, String> + Send + Sync>;

/// The provider of a task: the one it was given, replaced at the start of
/// each cycle when a source is set.
pub struct LiveProvider {
	current: Mutex<Arc<dyn DnsProvider>>,
	source: Option<ProviderSource>,
	/// Why the last build failed, so the same reason is logged once.
	failed: Mutex<Option<String>>,
}

impl LiveProvider {
	/// The provider `provider`, never built again.
	pub fn fixed(provider: Arc<dyn DnsProvider>) -> Self {
		LiveProvider {
			current: Mutex::new(provider),
			source: None,
			failed: Mutex::new(None),
		}
	}

	/// `provider` until the first cycle builds it again from `source`.
	pub fn from_source(provider: Arc<dyn DnsProvider>, source: ProviderSource) -> Self {
		let mut live = Self::fixed(provider);
		live.with_source(source);
		live
	}

	/// Build the provider from `source` at the start of every cycle.
	pub fn with_source(&mut self, source: ProviderSource) {
		self.source = Some(source);
	}

	/// The provider to write through now.
	pub fn get(&self) -> Arc<dyn DnsProvider> {
		Arc::clone(&self.current.lock().unwrap_or_else(PoisonError::into_inner))
	}

	/// Build the provider again when a source is set. On failure the provider
	/// of the last cycle is kept and the reason returned; the caller decides
	/// whether it writes with it.
	pub fn refresh(&self) -> Result<(), String> {
		let Some(source) = &self.source else {
			return Ok(());
		};
		let built = source()?;
		*self.current.lock().unwrap_or_else(PoisonError::into_inner) = built;
		Ok(())
	}

	/// [`Self::refresh`] for a task that keeps writing with the provider of
	/// the last cycle when the build fails, which it says once per reason in
	/// the log: a credential file the process can no longer read (after it
	/// dropped its privileges, say) does not stop the task, and does not
	/// fill the log every minute either.
	pub fn refresh_or_keep(&self, task: &str) {
		let outcome = self.refresh();
		let mut failed = self.failed.lock().unwrap_or_else(PoisonError::into_inner);
		match outcome {
			Ok(()) => *failed = None,
			Err(reason) => {
				if failed.as_deref() != Some(reason.as_str()) {
					tracing::warn!(%reason, task, "the DNS provider could not be built again; the one built before keeps writing");
				}
				*failed = Some(reason);
			}
		}
	}
}

impl DnsProvider for LiveProvider {
	fn check_access<'a>(
		&'a self,
		zone: &'a str,
		names: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		let provider = self.get();
		Box::pin(async move { provider.check_access(zone, names).await })
	}
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let (provider, zone) = (self.get(), zone.to_string());
		Box::pin(async move { provider.upsert(&zone, record).await })
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let (provider, zone) = (self.get(), zone.to_string());
		Box::pin(async move { provider.delete(&zone, record).await })
	}
	fn delete_exact(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let (provider, zone) = (self.get(), zone.to_string());
		Box::pin(async move { provider.delete_exact(&zone, record).await })
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let (provider, zone) = (self.get(), zone.to_string());
		Box::pin(async move { provider.list(&zone).await })
	}
	fn flattens_apex_cname(&self, zone: &str) -> bool {
		self.get().flattens_apex_cname(zone)
	}
	fn has_zone<'a>(&'a self, zone: &'a str) -> ZoneOp<'a> {
		let provider = self.get();
		Box::pin(async move { provider.has_zone(zone).await })
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		let provider = self.get();
		Box::pin(async move { provider.publish_snapshot(zone).await })
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		let provider = self.get();
		Box::pin(async move { provider.apply_guarded(zone, change).await })
	}
	fn lookup_operation<'a>(&'a self, operation_id: &'a str) -> OperationOp<'a> {
		let provider = self.get();
		Box::pin(async move { provider.lookup_operation(operation_id).await })
	}
}
