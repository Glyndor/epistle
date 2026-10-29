//! The upsert contract against the Porkbun mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.

use super::*;
use crate::dns::providers::tests::listing_contract::{
	CAA_VALUE, HOSTILE_TYPE, HTTPS_VALUE, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE, SVCB_VALUE, Shape,
	assert_kinds_kept,
};
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

/// A zone holding the sibling (id 1, listed first) and the old DKIM key
/// (id 2) at the same name.
async fn zone_with_sibling_and_old_key() -> (PorkbunProvider, Shared) {
	mock(serde_json::json!([
		stored("1", NAME, "TXT", SIBLING),
		stored("2", NAME, "TXT", OLD_DKIM),
	]))
	.await
}

fn writes(state: &Shared) -> Vec<String> {
	state
		.lock()
		.unwrap()
		.paths()
		.into_iter()
		.filter(|p| !p.starts_with("/dns/retrieve"))
		.map(str::to_string)
		.collect()
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert!(
		!writes(&state).iter().any(|w| w.ends_with("/1")),
		"the sibling was edited or deleted: {:?}",
		writes(&state)
	);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["/dns/edit/example.org/2"]);
	assert_eq!(
		state.lock().unwrap().body("/dns/edit/example.org/2")["content"],
		NEW_DKIM
	);
}

/// Two records of the same purpose are a configuration mistake the upsert
/// collapses: the first is edited, the other deleted, the sibling kept.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose_only() {
	let (provider, state) = mock(serde_json::json!([
		stored("1", NAME, "TXT", SIBLING),
		stored("2", NAME, "TXT", OLD_DKIM),
		stored("3", NAME, "TXT", "v=DKIM1; k=rsa; p=STRAY"),
	]))
	.await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert_eq!(
		writes(&state),
		vec!["/dns/edit/example.org/2", "/dns/delete/example.org/3"]
	);
}

/// Two SPF records at the apex plus one unrelated TXT (a site
/// verification token) is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a
/// third record. The apex in Porkbun is the empty label.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (provider, state) = mock(serde_json::json!([
		stored("1", "example.org", "TXT", OLD_SPF_1),
		stored("2", "example.org", "TXT", OLD_SPF_2),
		stored("3", "example.org", "TXT", UNRELATED),
	]))
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let writes = writes(&state);
	// Each old SPF record was either edited (/dns/edit/{id}) or
	// deleted (/dns/delete/{id}). Leaving either at the spot is
	// the bug the contract closes.
	let rec1_touched = writes
		.iter()
		.any(|w| w == "/dns/edit/example.org/1" || w == "/dns/delete/example.org/1");
	let rec2_touched = writes
		.iter()
		.any(|w| w == "/dns/edit/example.org/2" || w == "/dns/delete/example.org/2");
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
	// The unrelated TXT must not be touched.
	assert!(
		!writes
			.iter()
			.any(|w| w == "/dns/delete/example.org/3" || w == "/dns/edit/example.org/3"),
		"the unrelated TXT was deleted: {writes:?}"
	);
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let record = |id: &str, name: &str, kind: &str, content: &str| {
		serde_json::json!({
			"id": id, "name": name, "type": kind, "content": content,
			"ttl": "600", "prio": "0", "notes": ""
		})
	};
	let mut mx = record("7", "example.org", "MX", "mail.example.org");
	mx["prio"] = serde_json::json!("10");
	let (provider, _state) = mock(serde_json::json!([
		record("1", "sub.example.org", "NS", NS_TARGET),
		record("2", "example.org", "CAA", CAA_VALUE),
		record("3", "example.org", "HTTPS", HTTPS_VALUE),
		record("4", "example.org", "SVCB", SVCB_VALUE),
		mx,
		record("5", "example.org", "NAPTR", NAPTR_VALUE),
		record("6", "example.org", HOSTILE_TYPE, OPAQUE_VALUE),
	]))
	.await;
	let listed = provider.list("example.org").await.expect("list");
	assert_kinds_kept(&listed, &Shape::NAMED);
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
	let record = serde_json::json!({
		"id": "1", "name": "h.example.org", "type": "A", "content": "192.0.2.1",
		"ttl": "600", "prio": "0", "notes": ""
	});
	let (provider, _state) = mock(serde_json::json!(vec![record; 100_001])).await;
	let error = provider.list("example.org").await.expect_err("too many");
	assert_eq!(
		error,
		ProviderError::Remote(
			crate::dns::providers::tests::listing_contract::CAP_MESSAGE.to_string()
		)
	);
}
