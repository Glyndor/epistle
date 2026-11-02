//! The search for the zone of a name must stop at the entry that owns it, even
//! when that entry's provider cannot list or name zones.

use std::sync::{Arc, Mutex};

use super::super::*;
use crate::dns::provider::{ProviderError, RecordKind};

type Seen = Arc<Mutex<Vec<(&'static str, String)>>>;

/// A provider that holds its zone but cannot list it (Route 53, RFC 2136):
/// `list` is unsupported, so the default `has_zone` answers "no".
struct Unlisted {
	label: &'static str,
	seen: Seen,
}

impl DnsProvider for Unlisted {
	fn upsert(&self, zone: &str, _record: DnsRecord) -> Op<'_> {
		self.seen
			.lock()
			.unwrap()
			.push((self.label, zone.to_string()));
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, zone: &str, _record: DnsRecord) -> Op<'_> {
		self.seen
			.lock()
			.unwrap()
			.push((self.label, zone.to_string()));
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Err(ProviderError::Unsupported) })
	}
}

/// A provider that lists, so it answers "yes" to every zone it is asked about.
struct Lists {
	label: &'static str,
	seen: Seen,
}

impl DnsProvider for Lists {
	fn upsert(&self, zone: &str, _record: DnsRecord) -> Op<'_> {
		self.seen
			.lock()
			.unwrap()
			.push((self.label, zone.to_string()));
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn record(name: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: "v=spf1 -all".to_string(),
		ttl: 300,
		proxied: None,
	}
}

fn router(seen: &Seen) -> ZoneRouter {
	ZoneRouter::new(vec![
		(
			"example.org".into(),
			Arc::new(Lists {
				label: "parent",
				seen: seen.clone(),
			}),
		),
		(
			"eu.example.org".into(),
			Arc::new(Unlisted {
				label: "child",
				seen: seen.clone(),
			}),
		),
	])
}

#[tokio::test]
async fn the_search_stops_at_a_child_zone_whose_provider_cannot_list() {
	let seen = Seen::default();
	let router = router(&seen);
	let zone = crate::dns::zone::resolve(&router, "mail.eu.example.org")
		.await
		.unwrap();
	assert_eq!(zone, "eu.example.org", "the search climbed to the parent");
	router
		.upsert(&zone, record("mail.eu.example.org"))
		.await
		.unwrap();
	assert_eq!(
		*seen.lock().unwrap(),
		vec![("child", "eu.example.org".to_string())],
		"the parent's token must not see a name of the child zone"
	);
}

#[tokio::test]
async fn a_candidate_no_route_contains_is_not_a_zone() {
	let router = router(&Seen::default());
	assert!(!router.has_zone("example.com").await.unwrap());
	assert!(router.has_zone("eu.example.org").await.unwrap());
}

#[tokio::test]
async fn a_write_that_names_the_parent_zone_for_a_child_name_is_refused() {
	let seen = Seen::default();
	let router = router(&seen);
	for result in [
		router
			.upsert("example.org", record("mail.eu.example.org"))
			.await,
		router
			.delete("example.org", record("mail.eu.example.org"))
			.await,
	] {
		assert!(matches!(result, Err(ProviderError::Unsupported)));
	}
	assert!(seen.lock().unwrap().is_empty());
}
