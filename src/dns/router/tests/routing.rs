//! A call reaches the provider of its own zone and no other.

use std::sync::{Arc, Mutex};

use super::super::*;
use crate::dns::provider::{ProviderError, RecordKind};

/// A provider that remembers which zones it was asked about.
struct Recording {
	label: &'static str,
	seen: Arc<Mutex<Vec<(&'static str, String)>>>,
}

impl DnsProvider for Recording {
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
	fn list(&self, zone: &str) -> ListOp<'_> {
		self.seen
			.lock()
			.unwrap()
			.push((self.label, zone.to_string()));
		Box::pin(async { Ok(Vec::new()) })
	}
}

type Seen = Arc<Mutex<Vec<(&'static str, String)>>>;

fn recording(label: &'static str, seen: &Seen) -> Arc<dyn DnsProvider> {
	Arc::new(Recording {
		label,
		seen: seen.clone(),
	})
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

#[tokio::test]
async fn each_zone_reaches_its_own_provider() {
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![
		("example.org".into(), recording("a", &seen)),
		("example.net".into(), recording("b", &seen)),
	]);
	router
		.upsert("example.net", record("x.example.net"))
		.await
		.unwrap();
	router
		.delete("example.org", record("x.example.org"))
		.await
		.unwrap();
	router.list("mail.example.org").await.unwrap();
	let seen = seen.lock().unwrap().clone();
	assert_eq!(
		seen,
		vec![
			("b", "example.net".to_string()),
			("a", "example.org".to_string()),
			("a", "mail.example.org".to_string()),
		]
	);
}

#[tokio::test]
async fn the_longest_zone_owns_a_nested_zone() {
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![
		("example.org".into(), recording("parent", &seen)),
		("sub.example.org".into(), recording("child", &seen)),
	]);
	router
		.upsert("sub.example.org", record("a.sub.example.org"))
		.await
		.unwrap();
	router
		.upsert("example.org", record("a.example.org"))
		.await
		.unwrap();
	let seen = seen.lock().unwrap().clone();
	assert_eq!(seen[0].0, "child");
	assert_eq!(seen[1].0, "parent");
}

#[tokio::test]
async fn a_zone_without_an_entry_is_refused_and_touches_no_provider() {
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![("example.org".into(), recording("a", &seen))]);
	let error = router
		.upsert("example.net", record("x.example.net"))
		.await
		.unwrap_err();
	assert!(matches!(error, ProviderError::Unsupported));
	assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_name_that_only_ends_with_the_zone_text_is_another_zone() {
	// `evilexample.org` ends with `example.org` as text but is not below it.
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![("example.org".into(), recording("a", &seen))]);
	let error = router
		.upsert("evilexample.org", record("x.evilexample.org"))
		.await
		.unwrap_err();
	assert!(matches!(error, ProviderError::Unsupported));
	assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_zone_whose_entry_cannot_build_does_not_fall_back_to_its_parent() {
	// The child entry has no usable credential, so its route is the manual
	// provider. Its names must not reach the parent's token.
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![
		("example.org".into(), recording("parent", &seen)),
		("sub.example.org".into(), Arc::new(ManualProvider)),
	]);
	let error = router
		.upsert("sub.example.org", record("a.sub.example.org"))
		.await
		.unwrap_err();
	assert!(matches!(error, ProviderError::Unsupported));
	assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn zone_case_and_final_dot_do_not_change_the_owner() {
	let seen = Seen::default();
	let router = ZoneRouter::new(vec![("Example.ORG.".into(), recording("a", &seen))]);
	router
		.list("MAIL.example.org.")
		.await
		.expect("routed to the only entry");
	assert_eq!(seen.lock().unwrap().len(), 1);
}
