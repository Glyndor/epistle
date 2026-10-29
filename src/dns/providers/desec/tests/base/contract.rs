//! The upsert contract against the deSEC mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! deSEC's bulk PUT replaces the whole rrset, so the upsert has to carry the
//! siblings it read.

use super::*;
use crate::dns::providers::tests::listing_contract::{
	CAA_VALUE, HOSTILE_TYPE, HTTPS_VALUE, MX_DOTTED, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE,
	SVCB_VALUE, Shape, assert_kinds_kept,
};
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};
use crate::dns::txt::txt_presentation;

const NAME: &str = "sel._domainkey.example.org";

async fn upsert_over(existing: &[&str]) -> Vec<String> {
	let records: Vec<String> = existing.iter().map(|v| txt_presentation(v)).collect();
	let (provider, state) = mock(serde_json::json!([{
		"subname": "sel._domainkey", "type": "TXT", "ttl": 3600, "records": records,
	}]))
	.await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	let mut put = extract_records(&body);
	put.sort();
	put
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let put = upsert_over(&[SIBLING]).await;
	assert!(put.contains(&txt_presentation(SIBLING)), "{put:?}");
	assert!(put.contains(&txt_presentation(NEW_DKIM)), "{put:?}");
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let put = upsert_over(&[SIBLING, OLD_DKIM]).await;
	let mut expected = vec![txt_presentation(SIBLING), txt_presentation(NEW_DKIM)];
	expected.sort();
	assert_eq!(put, expected);
}

/// Two SPF records at the apex plus one unrelated TXT (a site
/// verification token) is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a
/// third record. A naive find-first-match implementation would update
/// record 1 and leave record 2, the bug the contract is closing.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let records: Vec<String> = [OLD_SPF_1, OLD_SPF_2, UNRELATED]
		.iter()
		.map(|v| txt_presentation(v))
		.collect();
	let (provider, state) = mock(serde_json::json!([{
		"subname": "", "type": "TXT", "ttl": 3600, "records": records,
	}]))
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let body = state.lock().unwrap().puts[0].clone();
	let mut put = extract_records(&body);
	put.sort();
	let new = txt_presentation(NEW_SPF);
	let unrelated = txt_presentation(UNRELATED);
	let mut expected = vec![unrelated, new];
	expected.sort();
	assert_eq!(
		put, expected,
		"the bulk PUT must carry exactly one SPF (new) and the unrelated TXT"
	);
	// No old SPF value reaches the wire.
	for v in [OLD_SPF_1, OLD_SPF_2] {
		let old = txt_presentation(v);
		assert!(!put.contains(&old), "old SPF value {v:?} re-published");
	}
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let rrset = |subname: &str, kind: &str, value: &str| serde_json::json!({"subname": subname, "type": kind, "ttl": 3600, "records": [value]});
	let (provider, _state) = mock(serde_json::json!([
		rrset("sub", "NS", NS_TARGET),
		rrset("", "CAA", CAA_VALUE),
		rrset("", "HTTPS", HTTPS_VALUE),
		rrset("", "SVCB", SVCB_VALUE),
		rrset("", "MX", MX_DOTTED),
		rrset("", "NAPTR", NAPTR_VALUE),
		rrset("", HOSTILE_TYPE, OPAQUE_VALUE),
	]))
	.await;
	let listed = provider.list("example.org").await.expect("list");
	assert_kinds_kept(
		&listed,
		&Shape {
			mx: MX_DOTTED,
			..Shape::NAMED
		},
	);
}

/// Kinds a listing shows but epistle does not publish are never written
/// or removed.
#[tokio::test]
async fn listed_only_kinds_are_never_written() {
	let (provider, _state) = mock(serde_json::json!([])).await;
	crate::dns::providers::tests::listing_contract::assert_listed_kinds_are_not_written(&provider)
		.await;
}

/// A zone with more records than a listing reads is an error, not a zone cut
/// short.
#[tokio::test]
async fn a_zone_past_the_record_cap_is_an_error() {
	let (provider, _state) = mock(serde_json::json!([
		{"subname": "", "type": "A", "ttl": 3600, "records": vec!["192.0.2.1"; 100_001]}
	]))
	.await;
	let error = provider.list("example.org").await.expect_err("too many");
	assert_eq!(
		error,
		ProviderError::Remote(
			crate::dns::providers::tests::listing_contract::CAP_MESSAGE.to_string()
		)
	);
}

/// deSEC answers 400 to a list past 500 rrsets unless a page is asked for
/// (`cursor=`), and names the next page in the `Link` header. The zone here
/// has two pages; a request without a cursor is refused as the real one is.
#[tokio::test]
async fn a_zone_past_500_rrsets_is_read_page_by_page() {
	use axum::extract::Query;
	use axum::http::{HeaderMap, StatusCode, header};
	use axum::response::IntoResponse;
	use std::collections::HashMap;

	async fn page(
		Query(query): Query<HashMap<String, String>>,
		headers: HeaderMap,
	) -> axum::response::Response {
		let host = headers[header::HOST].to_str().expect("host").to_string();
		let rrset = |subname: &str, kind: &str, value: &str| serde_json::json!({"subname": subname, "type": kind, "ttl": 3600, "records": [value]});
		match query.get("cursor").map(String::as_str) {
			None => (StatusCode::BAD_REQUEST, "pagination required").into_response(),
			Some("") => (
				[(
					header::LINK,
					format!("<http://{host}/domains/example.org/rrsets/?cursor=>; rel=\"first\", <http://{host}/domains/example.org/rrsets/?cursor=p2>; rel=\"next\""),
				)],
				axum::Json(serde_json::json!([rrset("", "A", "192.0.2.1")])),
			)
				.into_response(),
			Some("p2") => (
				[(
					header::LINK,
					format!("<http://{host}/domains/example.org/rrsets/?cursor=>; rel=\"first\", <http://{host}/domains/example.org/rrsets/?cursor=>; rel=\"prev\""),
				)],
				axum::Json(serde_json::json!([rrset("sub", "NS", "ns1.delegated.example.")])),
			)
				.into_response(),
			Some(_) => StatusCode::NOT_FOUND.into_response(),
		}
	}
	let app = axum::Router::new().route("/domains/{zone}/rrsets/", axum::routing::get(page));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DesecProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).expect("url"));
	let listed = provider.list("example.org").await.expect("list");
	let rows: Vec<(String, String, String)> = listed
		.iter()
		.map(|r| (r.name.clone(), format!("{:?}", r.kind), r.value.clone()))
		.collect();
	assert_eq!(
		rows,
		vec![
			(
				"example.org".to_string(),
				"A".to_string(),
				"192.0.2.1".to_string()
			),
			(
				"sub.example.org".to_string(),
				"Ns".to_string(),
				"ns1.delegated.example.".to_string()
			),
		]
	);
}

/// A `Link` header is read for its `next` entry only, whatever the order and
/// the quoting of its parameters.
#[test]
fn only_the_next_entry_of_a_link_header_is_followed() {
	assert_eq!(
		super::next_link(
			"<https://a/?cursor=>; rel=\"first\", <https://a/?cursor=n>; rel=\"next\""
		),
		Some("https://a/?cursor=n".to_string())
	);
	assert_eq!(
		super::next_link("<https://a/?cursor=n>; rel=next"),
		Some("https://a/?cursor=n".to_string())
	);
	assert_eq!(
		super::next_link(
			"<https://a/?cursor=>; rel=\"first\", <https://a/?cursor=p>; rel=\"prev\""
		),
		None
	);
	assert_eq!(super::next_link("garbage"), None);
}
