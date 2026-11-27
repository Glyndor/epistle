//! The resolver the DNS routes ask, and the limit on how many ask at once.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

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
	/// The turn keys the checks in progress hold: one per configured tenant
	/// a confined key reaches, or one per domain no tenant owns.
	turns: Arc<Mutex<HashSet<TurnKey>>>,
}

/// Who holds a turn: the configured tenant that owns a domain, or the domain
/// itself when no configured tenant owns it. Every domain of one tenant
/// answers the same key, so two keys of one tenant share a turn whatever
/// domains they name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TurnKey {
	/// The tenant's place in the configured list.
	Tenant(usize),
	/// A domain no configured tenant owns.
	Domain(String),
}

/// A turn: the keys it holds, given back when it is dropped so the set only
/// holds what is running.
struct Turn {
	turns: Arc<Mutex<HashSet<TurnKey>>>,
	keys: Vec<TurnKey>,
}

impl Drop for Turn {
	fn drop(&mut self) {
		let mut held = self
			.turns
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		for key in &self.keys {
			held.remove(key);
		}
	}
}

/// The place of one check in progress. Dropping it, however the check ends,
/// gives back the permit and the turns it holds.
pub(crate) struct DnsPlace {
	_permit: tokio::sync::OwnedSemaphorePermit,
	_turn: Option<Turn>,
}

impl Default for DnsChecks {
	fn default() -> Self {
		DnsChecks {
			lookup: None,
			gate: Arc::new(tokio::sync::Semaphore::new(MAX_DNS_CHECKS)),
			turns: Arc::default(),
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
	/// [`MAX_DNS_CHECKS`] are already running, or when the turn of the
	/// tenant the key belongs to is already held. A key with no domain
	/// restriction reaches every domain and is held to the shared limit
	/// only; a confined one can never take every place, so one tenant cannot
	/// keep the others out of the check.
	///
	/// The turn belongs to the tenant, not to the domains the key names: two
	/// keys of one tenant share it whatever domains they reach, so they
	/// cannot take the two places between them. A domain no tenant owns is a
	/// turn of its own.
	pub(crate) fn try_dns_check(&self, domains: Option<&[String]>) -> Option<DnsPlace> {
		let turn = match domains {
			Some(domains) => {
				let keys = self.turn_keys(domains);
				let turns = Arc::clone(&self.inner.dns.turns);
				let mut held = turns
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
				// One lock for the whole set: a key that reaches two tenants
				// takes both turns or none of them.
				if keys.iter().any(|key| held.contains(key)) {
					return None;
				}
				for key in &keys {
					held.insert(key.clone());
				}
				drop(held);
				// From here the turn is given back by its drop, whether the
				// permit below is taken or not.
				Some(Turn { turns, keys })
			}
			None => None,
		};
		let permit = Arc::clone(&self.inner.dns.gate).try_acquire_owned().ok()?;
		Some(DnsPlace {
			_permit: permit,
			_turn: turn,
		})
	}

	/// The turn keys of a key confined to `domains`: the configured tenant
	/// that owns each domain, or the domain itself when no tenant owns it.
	/// The keys are unique, so a key that names two domains of one tenant
	/// holds one turn.
	fn turn_keys(&self, domains: &[String]) -> Vec<TurnKey> {
		let mut keys: Vec<TurnKey> = Vec::new();
		for domain in domains {
			let domain = domain.to_ascii_lowercase();
			let key = match self.inner.tenant_limits.tenant_index_of_domain(&domain) {
				Some(tenant) => TurnKey::Tenant(tenant),
				None => TurnKey::Domain(domain),
			};
			if !keys.contains(&key) {
				keys.push(key);
			}
		}
		keys
	}

	/// How many turn keys the checks in progress hold.
	#[cfg(test)]
	pub(crate) fn dns_turn_keys_in_progress(&self) -> usize {
		self.inner
			.dns
			.turns
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.len()
	}

	/// How many of the shared places are taken.
	#[cfg(test)]
	pub(crate) fn dns_places_in_progress(&self) -> usize {
		MAX_DNS_CHECKS - self.inner.dns.gate.available_permits()
	}
}
