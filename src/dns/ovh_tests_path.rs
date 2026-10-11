//! Identifiers are data in the request target, and the OVH signature covers
//! the exact URL that is sent: the two must stay the same string.

use super::*;
use crate::dns::uri_probe::{probe, probe_with_headers};

fn provider(zone: &str, base: HttpsUrl) -> OvhProvider {
	OvhProvider::new(
		"ak".to_string(),
		"as".to_string(),
		ScopedSecret::new(zone, "ck"),
	)
	.with_base(base)
}

#[tokio::test]
async fn zone_is_one_escaped_segment_and_the_signature_covers_that_url() {
	let (base, seen, headers) = probe_with_headers(&["[]"]).await;
	let zone = "a/b?c.org";
	let provider = provider(zone, base.clone());
	provider.list(zone).await.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		["GET /domain/zone/a%2Fb%3Fc.org/record"]
	);
	let headers = headers.lock().unwrap();
	let timestamp: u64 = headers[0]["x-ovh-timestamp"]
		.to_str()
		.unwrap()
		.parse()
		.expect("timestamp");
	let signed_url = format!("{}domain/zone/a%2Fb%3Fc.org/record", base.as_str());
	assert_eq!(
		headers[0]["x-ovh-signature"].to_str().unwrap(),
		provider.sign("GET", &signed_url, "", timestamp)
	);
}

#[tokio::test]
async fn record_filters_are_encoded_query_pairs() {
	let (base, seen) = probe(&["[]"]).await;
	provider("example.org", base)
		.delete(
			"example.org",
			DnsRecord {
				name: "x&subDomain=evil.example.org".to_string(),
				kind: RecordKind::A,
				value: String::new(),
				ttl: 300,
			},
		)
		.await
		.expect("delete of an absent record is Ok");
	assert_eq!(
		*seen.lock().unwrap(),
		["GET /domain/zone/example.org/record?fieldType=A&subDomain=x%26subDomain%3Devil"]
	);
}
