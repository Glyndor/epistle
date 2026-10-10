//! GoDaddy provider tests, second half. Split from `godaddy_tests.rs` to stay
//! under the per-file line limit; the harness (`mock`, `mock_with`,
//! `mock_with_per_name`, `MockState`, `parse_per_name`, the axum
//! handlers, and `txt`) lives in the first half.

use axum::http::Method;

use super::tests::{mock, mock_with, mock_with_per_name, mock_with_per_name_raw, txt};
use super::*;

#[tokio::test]
async fn upsert_keeps_unrelated_apex_txt_when_set_already_has_one() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "@".to_string()),
		serde_json::json!([
			{"data": "google-site-verification=abc123", "ttl": 3600},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Txt,
				value: "v=spf1 mx -all".into(),
				ttl: 3600,
			},
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.len(), 2, "GET then PUT, never DELETE");
	assert_eq!(s.calls[0].method, Method::GET);
	assert_eq!(s.calls[0].path, "/domains/example.org/records/TXT/@");
	assert_eq!(s.calls[1].method, Method::PUT);
	assert_eq!(s.calls[1].path, "/domains/example.org/records/TXT/@");
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 2, "ownership TXT kept, SPF appended");
	let data: Vec<&str> = arr
		.iter()
		.map(|e| e["data"].as_str().expect("data string"))
		.collect();
	assert!(data.contains(&"google-site-verification=abc123"));
	assert!(data.contains(&"v=spf1 mx -all"));
}

/// A second upsert with the same value replaces the matching element
/// rather than appending a duplicate; the unrelated record the previous
/// test seeded is still kept. The TTL on the request (1800) differs
/// from the TTL on the seeded record (3600) so a regression that
/// kept the old TTL (the `*element = new_element.clone()` line gone
/// while the assignment still happened, or a compare that
/// accidentally included the TTL) would still pass a same-TTL
/// variant but fails here. The TTL replacement is the same path
/// as the value replacement: the matched element is overwritten
/// with the new element, which carries the new TTL.
#[tokio::test]
async fn upsert_replaces_matching_value_and_keeps_others() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "@".to_string()),
		serde_json::json!([
			{"data": "google-site-verification=abc123", "ttl": 3600},
			{"data": "v=spf1 mx -all", "ttl": 3600},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Txt,
				value: "v=spf1 mx -all".into(),
				ttl: 1800,
			},
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].method, Method::PUT);
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 2, "ownership kept, SPF replaced not duplicated");
	let data: Vec<&str> = arr
		.iter()
		.map(|e| e["data"].as_str().expect("data string"))
		.collect();
	assert!(data.contains(&"google-site-verification=abc123"));
	assert!(data.contains(&"v=spf1 mx -all"));
	let spf: &serde_json::Value = arr
		.iter()
		.find(|e| e["data"] == "v=spf1 mx -all")
		.expect("new SPF in the body");
	assert_eq!(
		spf["ttl"], 1800,
		"replacement carries the new TTL, not the old one"
	);
}

/// The apex absolute name is accepted with or without a trailing
/// presentation dot: `example.org` and `example.org.` must both
/// land on the `@` path the API expects. The FQDN-to-relative
/// converter already strips the trailing dot before comparing; the
/// case-insensitive authorisation check has to do the same or the
/// FQDN form would be rejected up front even though the converter
/// would map it to `@`.
#[tokio::test]
async fn fqdn_to_relative_accepts_a_trailing_dot_on_the_apex() {
	let (provider, state) = mock().await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org.".into(),
				kind: RecordKind::A,
				value: "203.0.113.10".into(),
				ttl: 600,
			},
		)
		.await
		.expect("trailing-dot apex upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].path, "/domains/example.org/records/A/@");
}

/// GoDaddy's DELETE removes every record at `(type, name)`. A naive
/// delete on a multi-value name would wipe every value at the owner,
/// which is the bug a stale ACME challenge cleanup would otherwise
/// trigger against a second certificate order at the same owner. The
/// delete path reads the live set, drops only the matching value, and
/// PUTs the remainder back.
#[tokio::test]
async fn delete_keeps_the_other_acme_challenge_value() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "_acme-challenge".to_string()),
		serde_json::json!([
			{"data": "token-aaaa", "ttl": 60},
			{"data": "token-bbbb", "ttl": 60},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(
		s.calls.len(),
		2,
		"GET then PUT, never DELETE on a partial set"
	);
	assert_eq!(s.calls[0].method, Method::GET);
	assert_eq!(
		s.calls[0].path,
		"/domains/example.org/records/TXT/_acme-challenge"
	);
	assert_eq!(s.calls[1].method, Method::PUT);
	assert_eq!(
		s.calls[1].path,
		"/domains/example.org/records/TXT/_acme-challenge"
	);
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 1, "only the matching value removed");
	assert_eq!(arr[0]["data"], "token-bbbb");
}

/// A zone authored with the presentation-form trailing dot
/// (`zone = "example.org."`) must reach the same GoDaddy path as the
/// dotless form. The provider strips the trailing dot on construction
/// so the URL the request goes to matches the API's
/// `/domains/{zone}/records/...` shape; without the strip the request
/// would miss every route and the test would see no captured calls.
#[tokio::test]
async fn zone_with_a_trailing_dot_is_normalised_to_a_dotless_path() {
	let (base, state) = mock_with_per_name_raw(serde_json::json!([]), Default::default()).await;
	let provider = GodaddyProvider::new(
		"ak_under_test".to_string(),
		"sk_under_test_secret".to_string(),
		"example.org.".to_string(),
	)
	.with_base(base);
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("trailing-dot zone upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[0].path, "/domains/example.org/records/TXT/@");
	assert_eq!(s.calls[1].path, "/domains/example.org/records/TXT/@");
}

/// Upserting an SPF at the apex must replace the matching SPF
/// (same version tag) without disturbing the other TXT records at
/// the same owner. The set the API returns has a domain-verification
/// token and an SPF; the new SPF replaces the matching element, the
/// ownership token stays, and the result has exactly two records,
/// the kept token and the new SPF, with no second SPF appended. A
/// second SPF at the same owner would cause an SPF `permerror`
/// (RFC 7208 §4.5), which is the bug the contract is closing.
#[tokio::test]
async fn upsert_spf_at_apex_with_ownership_txt_replaces_only_the_spf() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "@".to_string()),
		serde_json::json!([
			{"data": "google-site-verification=abc123", "ttl": 3600},
			{"data": "v=spf1 -all", "ttl": 3600},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Txt,
				value: "v=spf1 mx -all".into(),
				ttl: 3600,
			},
		)
		.await
		.expect("apex SPF change");
	let s = state.lock().unwrap();
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 2, "ownership kept, SPF replaced, not duplicated");
	let data: Vec<&str> = arr
		.iter()
		.map(|e| e["data"].as_str().expect("data string"))
		.collect();
	assert!(
		data.contains(&"google-site-verification=abc123"),
		"ownership kept: {data:?}"
	);
	assert!(
		data.contains(&"v=spf1 mx -all"),
		"new SPF present: {data:?}"
	);
	assert!(!data.contains(&"v=spf1 -all"), "old SPF replaced: {data:?}");
}

/// Upserting an MX with the same target in a different case must
/// replace the existing record rather than append a second one.
/// GoDaddy stores the target as an FQDN with a trailing dot, so the
/// live set has `MAIL.Example.Org.`; epistle publishes the
/// dotless form. Without the case-insensitive compare, the
/// `elements_match_kind` would miss the existing record and the
/// PUT body would carry two MX entries for the same DNS target.
#[tokio::test]
async fn upsert_mx_with_a_different_case_target_replaces_rather_than_duplicates() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("MX".to_string(), "@".to_string()),
		serde_json::json!([
			{"data": "MAIL.Example.Org.", "ttl": 3600, "priority": 10},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Mx,
				value: "10 mail.example.org".into(),
				ttl: 3600,
			},
		)
		.await
		.expect("MX replacement");
	let s = state.lock().unwrap();
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(
		arr.len(),
		1,
		"uppercase MX replaced by the lowercase one, not duplicated"
	);
	assert_eq!(arr[0]["data"], "mail.example.org");
	assert_eq!(arr[0]["priority"], 10);
}

/// Deleting one of two ACME DNS-01 challenges at the same owner
/// must leave the sibling challenge in place. The matching uses
/// `same_txt_purpose`, so two untagged values that differ in their
/// data do not match; deleting one of them drops just the one
/// element. Without the purpose compare (or with a value-based
/// compare that strips trailing dots), the delete would either wipe
/// the whole set or drop both challenges, the bug that a stale
/// challenge cleanup would otherwise trigger against a second
/// certificate order at the same owner.
#[tokio::test]
async fn delete_keeps_the_sibling_challenge_when_values_differ() {
	// The existing test `delete_keeps_the_other_acme_challenge_value`
	// already covers the "two values, delete one" case for a
	// well-formed pair. This case differs: the two challenges have
	// different values (token-aaaa vs token-bbbb), so the
	// `same_txt_purpose` compare has to distinguish them by value
	// (both untagged, identical rule), and a dot-stripping compare
	// would also distinguish them because neither has a trailing
	// dot. The test pins the contract: two untagged values match
	// only when identical.
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "_acme-challenge".to_string()),
		serde_json::json!([
			{"data": "token-aaaa", "ttl": 60},
			{"data": "token-bbbb", "ttl": 60},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	let body: serde_json::Value = serde_json::from_str(&s.calls[1].body).expect("parse put body");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(arr.len(), 1, "only the matching value removed");
	assert_eq!(arr[0]["data"], "token-bbbb");
}

/// The error path on a non-array body must not echo the body itself.
/// A 200 with a diagnostic JSON such as
/// `{"authorization": "sso-key key:secret"}` would otherwise embed
/// the credential half that lives in the `Authorization` header the
/// request just sent, and `Display`/`Debug` on `ProviderError::Remote`
/// exposes the string verbatim to operators. The path and a fixed
/// flag are enough to act on; the body shape (non-array, parse error)
/// is reported as a status, not as the value.
#[tokio::test]
async fn fetch_set_does_not_embed_response_body_in_the_error() {
	// Seed the per-name store with a non-array body. The mock returns
	// the stored value verbatim, so the GET the upsert issues will see
	// an object where the provider expects an array. The provider must
	// report the shape mismatch without echoing the body.
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "@".to_string()),
		serde_json::json!({
			"authorization": "sso-key ak_under_test:sk_under_test_secret",
		}),
	);
	let (base, _state) = mock_with_per_name_raw(serde_json::json!([]), per_name).await;
	let provider = GodaddyProvider::new(
		"ak_under_test".to_string(),
		"sk_under_test_secret".to_string(),
		"example.org".to_string(),
	)
	.with_base(base);
	let err = provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Txt,
				value: "v=spf1 -all".into(),
				ttl: 3600,
			},
		)
		.await
		.expect_err("non-array body must error");
	let ProviderError::Remote(text) = err else {
		panic!("expected Remote, got {err:?}");
	};
	assert!(
		text.contains("non-array") || text.contains("unparseable"),
		"message must flag the shape, not echo the body: {text}"
	);
	// The literal body token. The diagnostic body we modelled has the
	// sensitive key, and that string must never reach the operator.
	assert!(
		!text.contains("authorization"),
		"body must not appear in the error message: {text}"
	);
	assert!(
		!text.contains("ak_under_test") && !text.contains("sk_under_test_secret"),
		"credential halves must not appear in the error message: {text}"
	);
}

/// The v1 endpoints' allowed-type set excludes TLSA: a TLSA publish
/// would be a 4xx round-trip, not a clean "this provider does not
/// support TLSA" verdict. The provider short-circuits the call
/// before any network request and surfaces the same `Unsupported`
/// the other providers use for kinds they cannot represent on the
/// wire. The mock would see the call if the short-circuit did not
/// fire.
#[tokio::test]
async fn upsert_tlsa_is_unsupported_and_does_not_reach_the_wire() {
	let (provider, state) = mock().await;
	let result = provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "_443._tcp.example.org".into(),
				kind: RecordKind::Tlsa,
				value: "3 1 1 ABCDEF".into(),
				ttl: 3600,
			},
		)
		.await;
	assert_eq!(result, Err(ProviderError::Unsupported));
	assert!(
		state.lock().unwrap().calls.is_empty(),
		"the unsupported short-circuit must fire before any HTTP call"
	);
}

/// A 200 with a body the wire shape does not expect carries the
/// request's credential half through serde's type-error text
/// (`invalid type: string "sso-key key:secret", expected u32`).
/// The list path's `serde_json::from_str(...).map_err(|e|
/// ProviderError::Remote(e.to_string()))` would expose that
/// string verbatim through `Display` and `Debug`. The path and
/// the shape (parse error) are enough to act on; the body is
/// not echoed into the error.
#[tokio::test]
async fn list_error_does_not_embed_response_body_in_serde_message() {
	let zone_records = serde_json::json!([serde_json::json!({
		"type": "A",
		"name": "@",
		"data": "203.0.113.10",
		"ttl": "sso-key ak_under_test:sk_under_test_secret",
	}),]);
	let (provider, _state) = mock_with(zone_records).await;
	let err = provider
		.list("example.org")
		.await
		.expect_err("malformed body must error");
	let rendered = format!("{err}");
	let debug = format!("{err:?}");
	for needle in ["ak_under_test", "sk_under_test_secret", "sso-key"] {
		assert!(
			!rendered.contains(needle) && !debug.contains(needle),
			"serde error text leaked {needle:?} through Display/Debug: {rendered} | {debug}"
		);
	}
}

/// The DKIM rotator's retire path issues a TXT delete with an
/// empty value, the contract's "drop every TXT at the owner"
/// operation. The GoDaddy provider must hit `DELETE` for that
/// call, not `GET` + `PUT` (which would compare "" against the
/// live DKIM TXT through `same_txt_purpose` (false, so the
/// DKIM TXT is PUT back unchanged, the retired selector stays
/// published, and the rotation state and the on-disk key file
/// are removed anyway)). The mock would record a PUT body
/// carrying the seed if the wholesale path did not fire.
#[tokio::test]
async fn delete_txt_with_empty_value_is_a_wholesale_delete() {
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "ed._domainkey".to_string()),
		serde_json::json!([
			{"data": "v=DKIM1; k=rsa; p=AAA", "ttl": 3600},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.delete(
			"example.org",
			DnsRecord {
				name: "ed._domainkey.example.org".into(),
				kind: RecordKind::Txt,
				value: String::new(),
				ttl: 3600,
			},
		)
		.await
		.expect("empty-value delete is wholesale");
	let s = state.lock().unwrap();
	// The wholesale path goes straight to DELETE: no GET (the seed
	// is irrelevant; the caller asked to drop every TXT at the
	// owner), and no PUT-back of the live set.
	assert_eq!(
		s.calls.len(),
		1,
		"empty-value delete does not GET or PUT, only DELETE"
	);
	assert_eq!(s.calls[0].method, Method::DELETE);
	assert_eq!(
		s.calls[0].path,
		"/domains/example.org/records/TXT/ed._domainkey"
	);
}
