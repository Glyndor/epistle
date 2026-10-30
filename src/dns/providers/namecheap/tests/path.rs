//! Namecheap takes its credentials as form parameters in the body of a POST:
//! the request line carries none of them, so neither a log nor an error that
//! quotes the URL can show the key.

use super::*;
use crate::dns::tests::uri_probe::probe;

#[tokio::test]
async fn credentials_stay_out_of_the_request_line() {
	let (base, seen) = probe(&["<ApiResponse Status=\"OK\"/>"]).await;
	let secret = ScopedSecret::new("example.org", "us&er=1:k/ey?x#f");
	let provider = NamecheapProvider::new(secret)
		.expect("token parses")
		.with_api_url(
			crate::net::HttpsUrl::loopback_http(&format!("{}xml.response", base)).unwrap(),
		);
	// The probe's reply carries no hosts; only the request line matters here.
	let _ = provider.list("example.org").await;
	assert_eq!(*seen.lock().unwrap(), ["POST /xml.response"]);
}

#[test]
fn the_production_and_sandbox_endpoints_are_https() {
	let production = NamecheapProvider::new(ScopedSecret::new("example.org", "u:k")).unwrap();
	assert_eq!(production.base.as_url().scheme(), "https");
	assert_eq!(NamecheapProvider::sandbox_url().as_url().scheme(), "https");
}
