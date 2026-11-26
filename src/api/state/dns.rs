//! The resolver the DNS routes ask, and the limit on how many ask at once.

use std::sync::Arc;

use crate::spf::DnsLookup;

use super::ApiState;

/// Checks of the live DNS that may run at once. A check makes a dozen
/// lookups for each name, so the routes that start one are for a few callers
/// at a time, not for a crowd.
pub(super) const MAX_DNS_CHECKS: usize = 2;

/// How the DNS routes reach the resolver.
pub(super) struct DnsChecks {
	/// A resolver to use in place of the system's, for the tests.
	lookup: Option<Arc<dyn DnsLookup>>,
	/// One permit per check in progress.
	gate: Arc<tokio::sync::Semaphore>,
}

impl Default for DnsChecks {
	fn default() -> Self {
		DnsChecks {
			lookup: None,
			gate: Arc::new(tokio::sync::Semaphore::new(MAX_DNS_CHECKS)),
		}
	}
}

impl ApiState {
	/// Answer the DNS routes through `lookup` and not the system resolver.
	/// Must be set before the state is shared.
	pub fn with_dns_lookup(mut self, lookup: Arc<dyn DnsLookup>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.dns.lookup = Some(lookup);
		}
		self
	}

	/// The resolver for one check: the one set, or a fresh one of the system.
	/// A fresh resolver reuses no answer an earlier check cached, so a record
	/// published a moment ago is not hidden behind the "no such name" that
	/// check got. The servers it asks may still hold their own.
	pub(crate) fn dns_lookup(&self) -> std::io::Result<Arc<dyn DnsLookup>> {
		match &self.inner.dns.lookup {
			Some(lookup) => Ok(Arc::clone(lookup)),
			None => Ok(Arc::new(crate::spf::SystemDns::from_system()?)),
		}
	}

	/// The place of one more check in progress, or `None` when
	/// [`MAX_DNS_CHECKS`] are already running.
	pub(crate) fn try_dns_check(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
		Arc::clone(&self.inner.dns.gate).try_acquire_owned().ok()
	}
}
