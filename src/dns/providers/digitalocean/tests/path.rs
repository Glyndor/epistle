//! The zone is data in the request path and the pagination link comes from
//! the response body: neither may steer the bearer token anywhere else.

use super::*;
use crate::dns::tests::uri_probe::probe;

fn provider(zone: &str, base: HttpsUrl) -> DigitaloceanProvider {
	DigitaloceanProvider::new(ScopedSecret::new(zone, "tok")).with_base(base)
}

#[tokio::test]
async fn zone_is_one_escaped_path_segment_and_filters_are_encoded() {
	let (base, seen) = probe(&[r#"{"domain_records":[],"links":{"pages":{}}}"#]).await;
	let zone = "a/../b?c=1.org";
	provider(zone, base).list(zone).await.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		["GET /v2/domains/a%2F..%2Fb%3Fc=1.org/records?per_page=200"]
	);
}

#[tokio::test]
async fn a_pagination_link_to_another_host_is_refused_without_a_request() {
	let (base, seen) = probe(&[
		r#"{"domain_records":[],"links":{"pages":{"next":"http://203.0.113.9/v2/domains/example.org/records?page=2"}}}"#,
	])
	.await;
	let err = provider("example.org", base)
		.list("example.org")
		.await
		.expect_err("the off-origin link is refused");
	assert_eq!(
		err,
		ProviderError::Remote("invalid request URL: link leaves the origin of the API base".into())
	);
	assert_eq!(
		seen.lock().unwrap().len(),
		1,
		"only the first page was fetched"
	);
}

#[tokio::test]
async fn a_relative_pagination_link_is_followed_on_the_same_origin() {
	let (base, seen) = probe(&[
		r#"{"domain_records":[],"links":{"pages":{"next":"/v2/domains/example.org/records?page=2"}}}"#,
		r#"{"domain_records":[],"links":{"pages":{}}}"#,
	])
	.await;
	provider("example.org", base)
		.list("example.org")
		.await
		.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"GET /v2/domains/example.org/records?per_page=200",
			"GET /v2/domains/example.org/records?page=2"
		]
	);
}
