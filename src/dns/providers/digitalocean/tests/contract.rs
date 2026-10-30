//! The upsert contract against the DigitalOcean mock: a TXT upsert
//! replaces the record of the same purpose and leaves every other TXT
//! at the name alone. Two records of the same purpose at the same name
//! are a configuration mistake every receiver turns into a permanent
//! error (SPF returns `permerror`, RFC 7208 §4.5; DMARC is ignored, RFC
//! 7489 §6.6.3), so the upsert collapses them into one carrying the new
//! value. A zone that starts with two `v=spf1` TXT plus one unrelated
//! TXT ends with exactly one SPF TXT (epistle's value) and the unrelated
//! TXT untouched.

use super::base::mock;
use super::*;
use crate::dns::providers::digitalocean::tests::base::Shared;
use crate::dns::providers::tests::listing_contract::{
	HOSTILE_TYPE, HTTPS_VALUE, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE, SVCB_VALUE, Shape,
	assert_kinds_kept,
};

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}

fn txt_at(name: &str, id: u64, content: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id, "type": "TXT", "name": name, "data": content, "ttl": 3600,
		"priority": null, "port": null, "weight": null, "flags": null, "tag": null
	})
}

fn writes(state: &Shared) -> Vec<String> {
	state
		.lock()
		.unwrap()
		.calls
		.iter()
		.filter(|c| !c.starts_with("GET"))
		.cloned()
		.collect()
}

#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (provider, state) = mock(
		vec![
			txt_at("@", 1, OLD_SPF_1),
			txt_at("@", 2, OLD_SPF_2),
			txt_at("@", 3, UNRELATED),
		],
		false,
	)
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let writes = writes(&state);
	// Each old SPF record was either updated (PUT to /records/{id})
	// or deleted (DELETE to /records/{id}). Leaving either at the
	// spot is the bug the contract closes.
	let rec1_touched = writes.iter().any(|w| {
		w == "PUT /v2/domains/example.org/records/1"
			|| w == "DELETE /v2/domains/example.org/records/1"
	});
	let rec2_touched = writes.iter().any(|w| {
		w == "PUT /v2/domains/example.org/records/2"
			|| w == "DELETE /v2/domains/example.org/records/2"
	});
	assert!(
		rec1_touched,
		"old SPF1 was not edited or deleted: {writes:?}"
	);
	assert!(rec2_touched, "old SPF2 was left in place: {writes:?}");
	// No body carries an old SPF value.
	for body in &state.lock().unwrap().bodies {
		assert!(
			!body.contains(OLD_SPF_1),
			"old SPF1 was re-published: {body}"
		);
		assert!(
			!body.contains(OLD_SPF_2),
			"old SPF2 was re-published: {body}"
		);
	}
	// Exactly one body carries the new SPF value.
	let fresh = state
		.lock()
		.unwrap()
		.bodies
		.iter()
		.filter(|b| b.contains(NEW_SPF))
		.count();
	assert_eq!(
		fresh,
		1,
		"exactly one SPF write carries the new value, bodies: {:?}",
		state.lock().unwrap().bodies
	);
	// The unrelated TXT must not be deleted.
	assert!(
		!writes
			.iter()
			.any(|w| w == "DELETE /v2/domains/example.org/records/3"),
		"the unrelated TXT was deleted: {writes:?}"
	);
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let record = |id: u64, name: &str, kind: &str, data: &str| {
		serde_json::json!({
			"id": id, "type": kind, "name": name, "data": data, "ttl": 3600,
			"priority": null, "port": null, "weight": null, "flags": null, "tag": null
		})
	};
	let (provider, _state) = mock(
		vec![
			record(1, "sub", "NS", NS_TARGET),
			{
				let mut caa = record(2, "@", "CAA", "letsencrypt.org");
				caa["flags"] = serde_json::json!(128);
				caa["tag"] = serde_json::json!("issuewild");
				caa
			},
			record(3, "@", "HTTPS", HTTPS_VALUE),
			record(4, "@", "SVCB", SVCB_VALUE),
			{
				let mut mx = record(7, "@", "MX", "mail.example.org");
				mx["priority"] = serde_json::json!(10);
				mx
			},
			record(5, "@", "NAPTR", NAPTR_VALUE),
			record(6, "@", HOSTILE_TYPE, OPAQUE_VALUE),
		],
		false,
	)
	.await;
	let listed = provider.list("example.org").await.expect("list");
	assert_kinds_kept(&listed, &Shape::NAMED);
}

/// A server that links every page to another page cannot keep a listing
/// going: it stops at the page cap with an error, not with a shorter zone.
#[tokio::test]
async fn a_listing_that_never_ends_stops_at_the_page_cap() {
	let (provider, state) = mock(Vec::new(), true).await;
	{
		let mut s = state.lock().unwrap();
		let own = s
			.next_url
			.clone()
			.expect("next url")
			.replace("/next", "/v2/domains/example.org/records");
		s.next_url = Some(own);
	}
	let error = provider.list("example.org").await.expect_err("endless");
	assert_eq!(
		error,
		ProviderError::Remote(
			"the example.org zone is larger than a listing reads (1000 pages, 100000 records)"
				.to_string()
		)
	);
	assert_eq!(state.lock().unwrap().calls.len(), 1000);
}

/// More records than a listing reads is an error too, from a single page.
#[tokio::test]
async fn a_listing_past_the_record_cap_is_an_error() {
	let record = serde_json::json!({
		"id": 1, "type": "A", "name": "h", "data": "192.0.2.1", "ttl": 3600,
		"priority": null, "port": null, "weight": null, "flags": null, "tag": null
	});
	let (provider, _state) = mock(vec![record; 100_001], false).await;
	let error = provider.list("example.org").await.expect_err("too many");
	assert_eq!(
		error,
		ProviderError::Remote(
			"the example.org zone is larger than a listing reads (1000 pages, 100000 records)"
				.to_string()
		)
	);
}

/// Kinds a listing shows but epistle does not publish are never written
/// or removed.
#[tokio::test]
async fn listed_only_kinds_are_never_written() {
	let (provider, _state) = mock(Vec::new(), false).await;
	crate::dns::providers::tests::listing_contract::assert_listed_kinds_are_not_written(&provider)
		.await;
}
