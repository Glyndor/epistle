//! Namecheap takes its credentials in the query string, so the key must be
//! encoded as one value and the request must never be able to carry it in
//! the clear.

use super::*;
use crate::dns::uri_probe::probe;

#[tokio::test]
async fn credentials_are_encoded_query_values() {
	let (base, seen) = probe(&["<ApiResponse Status=\"OK\"/>"]).await;
	let secret = ScopedSecret::new("example.org", "us&er=1:k/ey?x#f");
	let provider = NamecheapProvider::new(secret)
		.expect("token parses")
		.with_api_url(
			crate::net::HttpsUrl::loopback_http(&format!("{}xml.response", base)).unwrap(),
		);
	// The probe's reply carries no hosts; only the request line matters here.
	let _ = provider.list("example.org").await;
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /xml.response?ApiUser=us%26er%3D1&ApiKey=k%2Fey%3Fx%23f&UserName=us%26er%3D1&Command=namecheap.domains.dns.getHosts&SLD=example&TLD=org"
		]
	);
}

#[test]
fn the_production_and_sandbox_endpoints_are_https() {
	let production = NamecheapProvider::new(ScopedSecret::new("example.org", "u:k")).unwrap();
	assert_eq!(production.base.as_url().scheme(), "https");
	assert_eq!(NamecheapProvider::sandbox_url().as_url().scheme(), "https");
}
