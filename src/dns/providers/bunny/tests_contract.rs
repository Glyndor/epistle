//! The upsert contract against the Bunny mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.

use super::*;
use crate::dns::providers::listing_contract::{
	HTTPS_VALUE, NAPTR_VALUE, NS_TARGET, SVCB_VALUE, Shape, assert_kinds_kept,
};
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

/// A zone holding the sibling (id 1, listed first) and the old DKIM key
/// (id 2) at the same name.
async fn zone_with_sibling_and_old_key() -> (BunnyProvider, Shared) {
	let (provider, state) = mock().await;
	state.lock().unwrap().zone_detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 1, "Type": 3, "Name": "sel._domainkey", "Value": SIBLING, "Ttl": 3600 },
			{ "Id": 2, "Type": 3, "Name": "sel._domainkey", "Value": OLD_DKIM, "Ttl": 3600 }
		]
	});
	(provider, state)
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
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert!(
		!writes(&state).iter().any(|w| w.ends_with("/records/1")),
		"the sibling was written over: {:?}",
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
	assert_eq!(writes(&state), vec!["POST /dnszone/42/records/2"]);
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON");
	assert_eq!(body["Value"], NEW_DKIM);
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
	let (provider, state) = mock().await;
	state.lock().unwrap().zone_detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 1, "Type": 3, "Name": "", "Value": OLD_SPF_1, "Ttl": 3600 },
			{ "Id": 2, "Type": 3, "Name": "", "Value": OLD_SPF_2, "Ttl": 3600 },
			{ "Id": 3, "Type": 3, "Name": "", "Value": UNRELATED, "Ttl": 3600 }
		]
	});
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let writes = writes(&state);
	// Each old SPF record was either edited (POST with the new
	// value) or deleted (DELETE). Leaving either at the spot is
	// the bug the contract closes.
	let rec1_touched = writes
		.iter()
		.any(|w| w == "POST /dnszone/42/records/1" || w == "DELETE /dnszone/42/records/1");
	let rec2_touched = writes
		.iter()
		.any(|w| w == "POST /dnszone/42/records/2" || w == "DELETE /dnszone/42/records/2");
	assert!(
		rec1_touched,
		"old SPF1 was not edited or deleted: {writes:?}"
	);
	assert!(rec2_touched, "old SPF2 was left in place: {writes:?}");
	// No write carries an old SPF value.
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
	// Exactly one write carries the new SPF value (the chosen
	// implementation, edit-in-place or PUT-then-delete, picks
	// exactly one path per duplicate).
	let fresh = state
		.lock()
		.unwrap()
		.bodies
		.iter()
		.filter(|b| b.contains(&format!("\"Value\":\"{NEW_SPF}\"")))
		.count();
	assert_eq!(
		fresh, 1,
		"exactly one SPF write carries the new value, got {fresh}"
	);
	// The unrelated TXT must not be touched.
	assert!(
		!writes.iter().any(|w| w == "DELETE /dnszone/42/records/3"),
		"the unrelated TXT was deleted: {writes:?}"
	);
}

/// Bunny numbers its record types (`DnsRecordTypes`): 12 is an NS, 9 a CAA,
/// 14 an HTTPS, 13 an SVCB, 10 a PTR, and a number the enum does not list
/// is `TYPE<n>`. None of them is a TXT.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let (provider, state) = mock().await;
	let record = |id: u32, kind: u32, name: &str, value: &str| serde_json::json!({ "Id": id, "Type": kind, "Name": name, "Value": value, "Ttl": 3600 });
	state.lock().unwrap().zone_detail = serde_json::json!({
		"Id": 42,
		"Records": [
			record(1, 12, "sub", NS_TARGET),
			serde_json::json!({"Id": 2, "Type": 9, "Name": "", "Value": "letsencrypt.org", "Ttl": 3600, "Flags": 0, "Tag": "issue"}),
			serde_json::json!({"Id": 7, "Type": 4, "Name": "", "Value": "mail.example.org", "Ttl": 3600, "Priority": 10}),
			record(3, 14, "", HTTPS_VALUE),
			record(4, 13, "", SVCB_VALUE),
			record(5, 99, "", NAPTR_VALUE),
		]
	});
	let listed = provider.list("example.org").await.expect("list");
	let shape = Shape {
		unknown_as: "TYPE99",
		hostile_row: false,
		..Shape::NAMED
	};
	assert_kinds_kept(&listed, &shape);
}

/// Kinds a listing shows but epistle does not publish are never written
/// or removed.
#[tokio::test]
async fn listed_only_kinds_are_never_written() {
	let (provider, _state) = mock().await;
	crate::dns::providers::listing_contract::assert_listed_kinds_are_not_written(&provider).await;
}

/// A zone with more records than a listing reads is an error, not a zone cut
/// short.
#[tokio::test]
async fn a_zone_past_the_record_cap_is_an_error() {
	let (provider, state) = mock().await;
	let record =
		serde_json::json!({"Id": 1, "Type": 0, "Name": "h", "Value": "192.0.2.1", "Ttl": 3600});
	state.lock().unwrap().zone_detail =
		serde_json::json!({"Id": 42, "Records": vec![record; 100_001]});
	let error = provider.list("example.org").await.expect_err("too many");
	assert_eq!(
		error,
		ProviderError::Remote(crate::dns::providers::listing_contract::CAP_MESSAGE.to_string())
	);
}
