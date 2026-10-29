//! The zone a dns-01 challenge is published in and withdrawn from.
//!
//! The challenge is published in the zone that holds the challenge name,
//! and the withdrawal removes the record from that same zone. The provider
//! is not asked a second time: a lookup that fails when the order is over
//! must not send the removal to a zone that does not hold the record and
//! leave the TXT behind.

use super::*;
use crate::dns::provider::ProviderError;
use std::sync::atomic::{AtomicBool, Ordering};

/// A provider that records every write as `upsert ZONE NAME` or
/// `delete ZONE NAME`, answers the zone lookup for the zones it holds, and
/// can be told to fail the lookup afterwards, the way a provider that
/// cannot answer fails.
struct Journal {
	calls: Mutex<Vec<String>>,
	/// The zones the credential covers.
	zones: Vec<String>,
	/// When set, the zone lookup fails instead of answering.
	lookup_fails: AtomicBool,
}

impl Journal {
	fn new(zones: &[&str]) -> Self {
		Journal {
			calls: Mutex::new(Vec::new()),
			zones: zones.iter().map(|zone| zone.to_string()).collect(),
			lookup_fails: AtomicBool::new(false),
		}
	}
}

type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for Journal {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.calls
			.lock()
			.expect("calls")
			.push(format!("upsert {zone} {}", record.name));
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.calls
			.lock()
			.expect("calls")
			.push(format!("delete {zone} {}", record.name));
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		if self.lookup_fails.load(Ordering::Relaxed) {
			return Box::pin(async { Err(ProviderError::Remote("the lookup failed".into())) });
		}
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

/// Answers that every record is visible, so the publish does not wait.
struct Visible;

impl TxtVisibility for Visible {
	fn visible<'a>(
		&'a self,
		_name: &'a str,
		_value: &'a str,
	) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async { true })
	}
}

const TOKEN: &str = "token-aaaa";

/// A responder over a credential that covers `example.org`, and the
/// provider it writes through.
fn responder() -> (Arc<Journal>, Dns01) {
	let provider = Arc::new(Journal::new(&["example.org"]));
	let responder =
		Dns01::new(provider.clone(), Arc::new(Visible)).with_bounds(Duration::ZERO, Duration::ZERO);
	(provider, responder)
}

fn key() -> AccountKey {
	AccountKey::generate().expect("key").0
}

#[tokio::test]
async fn the_withdrawal_removes_the_record_from_the_zone_the_publish_used() {
	let (provider, responder) = responder();
	let key = key();
	responder
		.publish("mail.example.org", TOKEN, &key)
		.await
		.expect("publish");
	// The lookup fails once the order is over, the way a provider that
	// cannot answer fails. The record is in the zone the publish used,
	// and that is where it has to go.
	provider.lookup_fails.store(true, Ordering::Relaxed);
	responder.withdraw("mail.example.org", TOKEN, &key).await;
	assert_eq!(
		provider.calls.lock().expect("calls").as_slice(),
		&[
			"upsert example.org _acme-challenge.mail.example.org".to_string(),
			"delete example.org _acme-challenge.mail.example.org".to_string(),
		]
	);
}

#[tokio::test]
async fn a_withdrawal_without_a_published_challenge_removes_nothing() {
	// Nothing was published, so there is no zone to remove the record
	// from. The removal stays where it is instead of going to a zone
	// nobody named.
	let (provider, responder) = responder();
	responder.withdraw("mail.example.org", TOKEN, &key()).await;
	assert!(
		provider.calls.lock().expect("calls").is_empty(),
		"calls: {:?}",
		provider.calls.lock().expect("calls")
	);
}

#[tokio::test]
async fn each_challenge_is_withdrawn_from_its_own_zone() {
	// Two challenges of two orders, published in two zones. The
	// withdrawal of one does not take the other out.
	let provider = Arc::new(Journal::new(&["example.org", "example.net"]));
	let responder =
		Dns01::new(provider.clone(), Arc::new(Visible)).with_bounds(Duration::ZERO, Duration::ZERO);
	let key = key();
	responder
		.publish("mail.example.org", TOKEN, &key)
		.await
		.expect("publish");
	responder
		.publish("mail.example.net", "token-bbbb", &key)
		.await
		.expect("publish");
	responder.withdraw("mail.example.org", TOKEN, &key).await;
	responder
		.withdraw("mail.example.net", "token-bbbb", &key)
		.await;
	assert_eq!(
		provider.calls.lock().expect("calls").as_slice(),
		&[
			"upsert example.org _acme-challenge.mail.example.org".to_string(),
			"upsert example.net _acme-challenge.mail.example.net".to_string(),
			"delete example.org _acme-challenge.mail.example.org".to_string(),
			"delete example.net _acme-challenge.mail.example.net".to_string(),
		]
	);
}
