//! Identifiers (the zone name, and the ids the API returns) are data in the
//! request target: characters that mean something in a URL must not change
//! which resource the token reaches or add query parameters.

use super::*;
use crate::dns::uri_probe::probe;

#[tokio::test]
async fn zone_name_and_zone_id_are_escaped_in_the_request_target() {
	let (base, seen) = probe(&[r#"{"result":[{"id":"z/1?x=2"}]}"#, r#"{"result":[]}"#]).await;
	let provider = CloudflareProvider::new(ScopedSecret::new("a&b=c.org", "tok")).with_base(base);
	provider.list("a&b=c.org").await.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /zones?name=a%26b%3Dc.org",
			"GET /zones/z%2F1%3Fx=2/dns_records?per_page=100&page=1"
		]
	);
}

#[tokio::test]
async fn record_id_and_lookup_values_are_escaped_on_delete() {
	let (base, seen) = probe(&[
		r#"{"result":[{"id":"zone1"}]}"#,
		r#"{"result":[{"id":"r/9?y","name":"x.example.org","type":"A","content":"192.0.2.1","ttl":300}]}"#,
		r#"{}"#,
	])
	.await;
	let provider = CloudflareProvider::new(ScopedSecret::new("example.org", "tok")).with_base(base);
	provider
		.delete(
			"example.org",
			DnsRecord {
				name: "x.example.org".to_string(),
				kind: RecordKind::A,
				value: String::new(),
				ttl: 300,
				proxied: None,
			},
		)
		.await
		.expect("delete");
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /zones?name=example.org",
			"GET /zones/zone1/dns_records?type=A&name=x.example.org",
			"DELETE /zones/zone1/dns_records/r%2F9%3Fy"
		]
	);
}
