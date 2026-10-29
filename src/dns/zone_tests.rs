//! The zone that holds a record name, as the provider knows it.

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, ZoneOp};
use std::pin::Pin;
use std::sync::Mutex;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A provider that holds the zones it was given and refuses every other
/// one: the shape a credential scoped to a zone has, where a name below
/// the zone is not a zone of its own. It remembers every zone the search
/// asked about.
struct Zoned {
	zones: Vec<String>,
	asked: Mutex<Vec<String>>,
}

impl Zoned {
	fn new(zones: &[&str]) -> Self {
		Zoned {
			zones: zones.iter().map(|zone| zone.to_string()).collect(),
			asked: Mutex::new(Vec::new()),
		}
	}

	fn asked(&self) -> Vec<String> {
		self.asked.lock().expect("asked").clone()
	}
}

impl DnsProvider for Zoned {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		self.asked.lock().expect("asked").push(zone.to_string());
		let held = self.zones.iter().any(|held| held == zone);
		let zone = zone.to_string();
		Box::pin(async move {
			if held {
				Ok(Vec::new())
			} else {
				Err(ProviderError::ZoneNotFound(zone))
			}
		})
	}
}

/// A provider that answers the zone question the way the shared default
/// does — with a listing — and whose listing fails for one zone: that zone
/// did not answer, which is not the same as a zone that is not there.
struct ListFails {
	zones: Vec<String>,
	failing: Vec<String>,
}

impl DnsProvider for ListFails {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		let held = self.zones.iter().any(|held| held == zone);
		let failing = self.failing.iter().any(|failing| failing == zone);
		let zone = zone.to_string();
		Box::pin(async move {
			if failing {
				Err(ProviderError::Remote(
					"the provider did not answer".to_string(),
				))
			} else if held {
				Ok(Vec::new())
			} else {
				Err(ProviderError::ZoneNotFound(zone))
			}
		})
	}
}

/// A provider whose zone lookup fails with an error of its own.
struct Broken;

impl DnsProvider for Broken {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn has_zone(&self, _zone: &str) -> ZoneOp<'_> {
		Box::pin(async { Err(ProviderError::Auth) })
	}
}

#[test]
fn candidates_walk_the_labels_up_from_the_longest_name() {
	assert_eq!(
		candidates("mail.example.org"),
		vec!["mail.example.org", "example.org"]
	);
	assert_eq!(
		candidates("mail.sub.example.org"),
		vec!["mail.sub.example.org", "sub.example.org", "example.org"]
	);
	assert_eq!(candidates("example.org"), vec!["example.org"]);
	assert!(
		candidates("org").is_empty(),
		"a top-level label is not a zone"
	);
}

#[test]
fn candidates_are_lowercased_and_ignore_the_root_dot() {
	assert_eq!(
		candidates("Mail.Example.ORG."),
		vec!["mail.example.org", "example.org"]
	);
}

#[tokio::test]
async fn resolve_finds_the_zone_that_holds_the_name() {
	let provider = Zoned::new(&["example.org"]);
	assert_eq!(
		resolve(&provider, "mail.example.org").await.expect("zone"),
		"example.org"
	);
	// The search asks the provider, longest name first.
	assert_eq!(
		provider.asked(),
		vec!["mail.example.org".to_string(), "example.org".to_string()]
	);
}

#[tokio::test]
async fn resolve_prefers_the_longest_zone_the_provider_holds() {
	// A delegated subdomain is a zone of its own: the record below it
	// belongs there, not in the zone above.
	let provider = Zoned::new(&["example.org", "mail.example.org"]);
	assert_eq!(
		resolve(&provider, "mail.example.org").await.expect("zone"),
		"mail.example.org"
	);
}

#[tokio::test]
async fn resolve_keeps_the_name_when_the_provider_holds_no_zone() {
	// A provider that does not name zones lists every name, so the name
	// stays the zone: the write is refused by the provider with the zone
	// it could not find, exactly as before.
	let provider = Zoned::new(&[]);
	assert_eq!(
		resolve(&provider, "mail.example.org").await.expect("zone"),
		"mail.example.org"
	);
}

#[tokio::test]
async fn resolve_stops_when_the_provider_fails_to_answer() {
	// A lookup that fails is not a zone that does not exist: the search
	// stops there instead of writing into another zone.
	assert_eq!(
		resolve(&Broken, "mail.example.org")
			.await
			.expect_err("the failure is reported"),
		ProviderError::Auth
	);
}

#[tokio::test]
async fn resolve_stops_when_the_listing_of_the_child_zone_fails() {
	// The child zone only failed to answer and the parent is there. The
	// search stops at the child: the record belongs to the zone that
	// holds the name, and a zone that did not answer does not say that
	// the parent holds it.
	let provider = ListFails {
		zones: vec!["example.org".to_string()],
		failing: vec!["mail.example.org".to_string()],
	};
	assert_eq!(
		resolve(&provider, "mail.example.org")
			.await
			.expect_err("the failure is reported"),
		ProviderError::Remote("the provider did not answer".to_string())
	);
}
