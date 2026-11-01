//! Several DNS providers behind one [`DnsProvider`]: each call goes to the
//! provider that owns the zone it names, and to no other.
//!
//! The configuration may carry one credential per zone. Every feature that
//! writes DNS (DKIM rotation, the TLSA refresh, the ACME dns-01 challenge,
//! `dns lockdown`) already holds a provider and a zone, so the router is the
//! one place that picks the credential. A zone that no configured entry
//! contains behaves like the manual provider: writes are refused with
//! [`crate::dns::provider::ProviderError::Unsupported`], which every caller
//! already turns into "publish this record by hand", for that zone only.
//!
//! The pick is the entry with the longest zone that contains the zone of the
//! call, and it never falls back to another entry. A zone whose entry could
//! not be built (missing token file, empty variable) is still owned by that
//! entry and writes nothing: handing its names to the entry of a parent zone
//! would put the parent's token on a zone it was not configured for.

use std::sync::Arc;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ListOp, ManualProvider, Op, ProviderError, ZoneOp,
};
use crate::dns::providers::check::CheckOp;
use crate::dns::publish::provider::{Change, Receipt, ReceiptOp, SnapshotOp};

/// The provider of each configured zone.
pub struct ZoneRouter {
	/// `(zone, provider)` with the zone lowercase and without a final dot.
	routes: Vec<(String, Arc<dyn DnsProvider>)>,
	/// What a zone outside every route gets: no API, writes refused.
	unrouted: ManualProvider,
}

impl ZoneRouter {
	/// A router over `routes`, each a zone and the provider that owns it.
	pub fn new(routes: Vec<(String, Arc<dyn DnsProvider>)>) -> Self {
		let routes = routes
			.into_iter()
			.map(|(zone, provider)| (normalize(&zone), provider))
			.collect();
		ZoneRouter {
			routes,
			unrouted: ManualProvider,
		}
	}

	/// The index of the route that owns `name`: the one with the longest zone
	/// that equals it or contains it.
	fn index(&self, name: &str) -> Option<usize> {
		let name = normalize(name);
		self.routes
			.iter()
			.enumerate()
			.filter(|(_, (owned, _))| contains(owned, &name))
			.max_by_key(|(_, (owned, _))| owned.len())
			.map(|(index, _)| index)
	}

	/// The provider that owns `zone`. The manual provider when no route does.
	fn route(&self, zone: &str) -> &dyn DnsProvider {
		self.index(zone)
			.map_or(&self.unrouted as &dyn DnsProvider, |index| {
				self.routes[index].1.as_ref()
			})
	}

	/// Whether the route that owns `zone` also owns `name`. A record is
	/// written with the credential of the zone that holds its name, so a
	/// caller that hands over the zone of a parent for a name of a nested
	/// zone is refused instead of served with the parent's token.
	fn agrees(&self, zone: &str, name: &str) -> bool {
		self.index(zone) == self.index(name)
	}
}

/// Lowercase, without the final dot.
pub(crate) fn normalize(name: &str) -> String {
	name.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `name` equals `zone` or is below it. Both are normalized.
pub(crate) fn contains(zone: &str, name: &str) -> bool {
	name == zone
		|| name
			.strip_suffix(zone)
			.is_some_and(|rest| rest.ends_with('.'))
}

impl DnsProvider for ZoneRouter {
	fn check_access<'a>(&'a self, zone: &'a str, names: &'a [String]) -> CheckOp<'a> {
		self.route(zone).check_access(zone, names)
	}
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		if !self.agrees(zone, &record.name) {
			return Box::pin(async { Err(ProviderError::Unsupported) });
		}
		self.route(zone).upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		if !self.agrees(zone, &record.name) {
			return Box::pin(async { Err(ProviderError::Unsupported) });
		}
		self.route(zone).delete(zone, record)
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		self.route(zone).list(zone)
	}
	// A zone named in the configuration is a zone: the candidate that is
	// exactly a route's zone answers yes without asking, so the search for
	// the zone of a name stops there even when that provider cannot list or
	// name zones, and never climbs to the parent's route. A candidate no route
	// contains is not a zone of this router. One below a route's zone is the
	// provider's to answer.
	fn has_zone<'a>(&'a self, zone: &'a str) -> ZoneOp<'a> {
		match self.index(zone) {
			None => Box::pin(async { Ok(false) }),
			Some(index) if self.routes[index].0 == normalize(zone) => Box::pin(async { Ok(true) }),
			Some(index) => self.routes[index].1.has_zone(zone),
		}
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		self.route(zone).publish_snapshot(zone)
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		if !self.agrees(zone, &change.name) {
			return Box::pin(async { Receipt::Unsupported });
		}
		self.route(zone).apply_guarded(zone, change)
	}
	// `lookup_operation` keeps the default (unsupported): an operation id
	// names no zone, and asking every provider about it would send one
	// provider an id that belongs to another.
}

#[cfg(test)]
mod tests;
