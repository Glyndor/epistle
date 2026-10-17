//! The upsert contract against the Spaceship mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! Spaceship deletes a TXT by its exact value, so the upsert has to name the
//! OLD value of that purpose, never the new one.

use super::tests::mock;
use super::*;
use crate::dns::providers::listing_contract::{
	HOSTILE_TYPE, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE, Shape, assert_kinds_kept,
};
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

fn txt(value: &str) -> DnsRecord {
	DnsRecord {
		name: "sel._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: value.into(),
		ttl: 3600,
		proxied: None,
	}
}

fn stored(value: &str) -> serde_json::Value {
	serde_json::json!({"type": "TXT", "name": "sel._domainkey", "value": value, "ttl": 3600})
}

/// The values every DELETE named, and the values every save added.
async fn upsert_over(existing: &[&str], value: &str) -> (Vec<String>, Vec<String>) {
	let (provider, state) = mock(existing.iter().map(|v| stored(v)).collect()).await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let writes = s.calls.iter().filter(|c| !c.starts_with("GET"));
	let (mut deleted, mut saved) = (Vec::new(), Vec::new());
	for (call, body) in writes.zip(&s.bodies) {
		let body: serde_json::Value = serde_json::from_str(body).expect("JSON");
		if call.starts_with("DELETE") {
			for item in body.as_array().expect("array") {
				deleted.push(item["value"].as_str().unwrap_or("<wholesale>").to_string());
			}
		} else {
			for item in body["items"].as_array().expect("items") {
				saved.push(item["value"].as_str().expect("value").to_string());
			}
		}
	}
	(deleted, saved)
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (deleted, saved) = upsert_over(&[SIBLING], NEW_DKIM).await;
	assert!(!deleted.iter().any(|v| v == SIBLING), "{deleted:?}");
	assert!(!deleted.iter().any(|v| v == "<wholesale>"), "{deleted:?}");
	assert_eq!(saved, vec![NEW_DKIM.to_string()]);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let (deleted, saved) = upsert_over(&[SIBLING, OLD_DKIM], NEW_DKIM).await;
	assert_eq!(deleted, vec![OLD_DKIM.to_string()]);
	assert_eq!(saved, vec![NEW_DKIM.to_string()]);
}

/// Two SPF records at the same name plus one unrelated TXT (a site
/// verification token) is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a
/// third record. Spaceship's API matches deletes by exact value, so
/// the test seeds two SPF records and confirms both end up removed
/// (one DELETE per old value, one PUT for the new one).
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (deleted, saved) = upsert_over(&[OLD_SPF_1, OLD_SPF_2, UNRELATED], NEW_SPF).await;
	// Both old SPF records were DELETEd; the new SPF was added.
	let mut deleted_sorted = deleted.clone();
	deleted_sorted.sort();
	let mut want_deleted = vec![OLD_SPF_1.to_string(), OLD_SPF_2.to_string()];
	want_deleted.sort();
	assert_eq!(
		deleted_sorted, want_deleted,
		"both old SPF records must be deleted"
	);
	assert_eq!(saved, vec![NEW_SPF.to_string()]);
	// The unrelated TXT must not be deleted.
	assert!(
		!deleted.contains(&UNRELATED.to_string()),
		"the unrelated TXT was deleted: {deleted:?}"
	);
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
/// Spaceship names the value field after the type: an NS carries
/// `nameserver`, an HTTPS or SVCB `svcPriority`, `targetName` and
/// `svcParams`, a CAA `flag`, `tag` and `value`. A listing that looks for a
/// `value` only drops them all.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let (provider, _state) = mock(vec![
		serde_json::json!({"type": "NS", "name": "sub", "nameserver": NS_TARGET, "ttl": 3600}),
		serde_json::json!({
			"type": "CAA", "name": "@", "flag": 0, "tag": "issue",
			"value": "letsencrypt.org", "ttl": 3600
		}),
		serde_json::json!({
			"type": "HTTPS", "name": "@", "svcPriority": 1, "targetName": ".",
			"svcParams": "alpn=\"h2\"", "ttl": 3600
		}),
		serde_json::json!({
			"type": "SVCB", "name": "@", "svcPriority": 1, "targetName": "svc.example.net.",
			"svcParams": "port=8443", "ttl": 3600
		}),
		serde_json::json!({"type": "NAPTR", "name": "@", "value": NAPTR_VALUE, "ttl": 3600}),
		serde_json::json!({"type": HOSTILE_TYPE, "name": "@", "value": OPAQUE_VALUE, "ttl": 3600}),
	])
	.await;
	let listed = provider.list("example.org").await.expect("list");
	assert_kinds_kept(&listed, &Shape::NAMED);
}

/// A server that claims an endless `total` cannot keep a listing going: it
/// stops at the page cap with an error, not with a shorter zone.
#[tokio::test]
async fn a_listing_that_claims_an_endless_total_stops_at_the_page_cap() {
	let (provider, state) = mock(vec![
		serde_json::json!({"type": "A", "name": "h", "address": "192.0.2.1", "ttl": 3600}),
	])
	.await;
	state.lock().unwrap().total = Some(i64::MAX);
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
