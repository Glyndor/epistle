//! The TLSA record of a replaced certificate, published in the zone that
//! holds the mail hostname.

use super::*;
use crate::dns::provider::{DnsProvider, ProviderError};
use std::pin::Pin;
use std::sync::Mutex;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// The zone this provider holds.
const ZONE: &str = "example.org";

/// A provider that holds one zone, `example.org`, and refuses every other
/// one: the shape a credential scoped to a zone has, where a name below
/// the zone is not a zone of its own. A write into a zone it does not
/// hold fails the way a provider's zone lookup does.
#[derive(Default)]
struct OneZone {
	upserts: Mutex<Vec<PublishRecord>>,
}

impl DnsProvider for OneZone {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.upserts.lock().expect("upserts").push(PublishRecord {
			zone: zone.to_string(),
			record,
		});
		let zone = zone.to_string();
		Box::pin(async move {
			if zone == ZONE {
				Ok(())
			} else {
				Err(ProviderError::Remote(format!("zone not found: {zone}")))
			}
		})
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		Box::pin(async move {
			if zone == ZONE {
				Ok(Vec::new())
			} else {
				Err(ProviderError::Remote(format!("zone not found: {zone}")))
			}
		})
	}
}

#[tokio::test]
async fn publish_tlsa_uses_the_zone_that_holds_the_mail_hostname() {
	let cert = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
		.expect("self-signed");
	let provider = OneZone::default();
	publish_tlsa(&provider, "mail.example.org", &cert.cert.pem())
		.await
		.expect("the record is published in the zone that holds the hostname");
	let upserts = provider.upserts.lock().expect("upserts");
	assert_eq!(upserts.len(), 1, "one record");
	assert_eq!(
		upserts[0].zone, ZONE,
		"the zone that holds the mail hostname"
	);
	assert_eq!(upserts[0].record.name, "_25._tcp.mail.example.org");
}
