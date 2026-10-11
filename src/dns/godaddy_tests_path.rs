//! The zone and the record name are data in the request path: characters that
//! mean something in a URL must not change which resource the key pair reaches.

use super::*;
use crate::dns::uri_probe::probe;

fn provider(zone: &str, base: HttpsUrl) -> GodaddyProvider {
	GodaddyProvider::new("ak".to_string(), "sk".to_string(), zone.to_string()).with_base(base)
}

fn txt(name: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: "v=spf1 -all".to_string(),
		ttl: 3600,
	}
}

#[tokio::test]
async fn record_name_with_slash_and_query_characters_is_one_path_segment() {
	let (base, seen) = probe(&["[]"]).await;
	provider("example.org", base)
		.upsert("example.org", txt("a/b?c=1.example.org"))
		.await
		.expect("upsert");
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /domains/example.org/records/TXT/a%2Fb%3Fc=1",
			"PUT /domains/example.org/records/TXT/a%2Fb%3Fc=1"
		]
	);
}

#[tokio::test]
async fn zone_with_a_space_and_a_slash_is_one_path_segment() {
	let (base, seen) = probe(&["[]"]).await;
	provider("a b/c.org", base)
		.list("a b/c.org")
		.await
		.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		["GET /domains/a%20b%2Fc.org/records"]
	);
}
