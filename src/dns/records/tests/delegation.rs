//! A zone found by access is not proved to be the one that serves the
//! name: when the zone the credential sees delegates the name to other
//! nameservers, the TLSA record is not written there.

use super::*;
use crate::dns::provider::{DnsProvider, ProviderError};
use std::pin::Pin;
use std::sync::Mutex;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A provider that sees `example.org` only and lists what it was given.
struct Parent {
	listing: Vec<DnsRecord>,
	upserts: Mutex<Vec<PublishRecord>>,
}

impl Parent {
	fn with(listing: Vec<DnsRecord>) -> Self {
		Parent {
			listing,
			upserts: Mutex::new(Vec::new()),
		}
	}

	fn writes(&self) -> usize {
		self.upserts.lock().expect("upserts").len()
	}
}

impl DnsProvider for Parent {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.upserts.lock().expect("upserts").push(PublishRecord {
			zone: zone.to_string(),
			record,
		});
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let listing = self.listing.clone();
		Box::pin(async move {
			if zone == "example.org" {
				Ok(listing)
			} else {
				Err(ProviderError::ZoneNotFound(zone))
			}
		})
	}
}

fn ns(name: &str) -> DnsRecord {
	DnsRecord::new(name, RecordKind::Ns, "ns1.elsewhere.example.net", 3600)
}

fn pem(host: &str) -> String {
	rcgen::generate_simple_self_signed(vec![host.to_string()])
		.expect("self-signed")
		.cert
		.pem()
}

#[tokio::test]
async fn a_name_delegated_below_the_zone_is_not_written_there() {
	let provider = Parent::with(vec![ns("sub.example.org")]);
	let result = publish_tlsa(
		&provider,
		"mail.sub.example.org",
		&pem("mail.sub.example.org"),
	)
	.await;
	let error = result.expect_err("the parent zone does not serve the name");
	assert!(
		error.to_string().contains("delegated"),
		"the refusal says why: {error}"
	);
	assert_eq!(provider.writes(), 0, "nothing is written in the parent");
}

#[tokio::test]
async fn a_delegation_of_the_record_name_itself_is_refused() {
	let provider = Parent::with(vec![ns("_tcp.mail.example.org")]);
	let result = publish_tlsa(&provider, "mail.example.org", &pem("mail.example.org")).await;
	assert!(result.is_err(), "the record name sits under a zone cut");
	assert_eq!(provider.writes(), 0);
}

#[tokio::test]
async fn the_apex_name_servers_are_not_a_delegation() {
	let provider = Parent::with(vec![ns("example.org"), ns("other.example.org")]);
	publish_tlsa(&provider, "mail.example.org", &pem("mail.example.org"))
		.await
		.expect("an unrelated delegation does not stop the write");
	assert_eq!(provider.writes(), 1);
}

/// A provider that cannot read its zone, or whose listing fails.
struct Unreadable(ProviderError);

impl DnsProvider for Unreadable {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		let error = self.0.clone();
		Box::pin(async move { Err(error) })
	}

	fn has_zone<'a>(&'a self, _zone: &'a str) -> crate::dns::provider::ZoneOp<'a> {
		Box::pin(async { Ok(true) })
	}
}

#[tokio::test]
async fn a_provider_that_cannot_list_keeps_the_zone_the_operator_configured() {
	let provider = Unreadable(ProviderError::Unsupported);
	publish_tlsa(&provider, "mail.example.org", &pem("mail.example.org"))
		.await
		.expect("nothing to read, nothing to refuse");
}

#[tokio::test]
async fn a_listing_that_fails_stops_the_write() {
	let provider = Unreadable(ProviderError::Remote("timed out".to_string()));
	let result = publish_tlsa(&provider, "mail.example.org", &pem("mail.example.org")).await;
	assert_eq!(
		result,
		Err(ProviderError::Remote("timed out".to_string())),
		"a zone that did not answer is not proved to serve the name"
	);
}
