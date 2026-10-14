//! The upsert contract against the DNSimple mock: a TXT upsert replaces
//! the record of the same purpose and leaves every other TXT at the name
//! alone. Two records of the same purpose at the same name are a
//! configuration mistake (SPF returns `permerror`, RFC 7208 §4.5; DMARC
//! is ignored, RFC 7489 §6.6.3), so the upsert collapses them into one
//! carrying the new value. A zone that starts with two `v=spf1` TXT
//! plus one unrelated TXT ends with exactly one SPF TXT (epistle's
//! value) and the unrelated TXT untouched.

use super::tests::mock;
use super::*;
use crate::dns::providers::dnsimple::tests::Shared;

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
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
	let (provider, state) = mock(vec![
		serde_json::json!({"id": 1, "type": "TXT", "name": "", "content": OLD_SPF_1, "ttl": 3600, "priority": null, "weight": null, "port": null}),
		serde_json::json!({"id": 2, "type": "TXT", "name": "", "content": OLD_SPF_2, "ttl": 3600, "priority": null, "weight": null, "port": null}),
		serde_json::json!({"id": 3, "type": "TXT", "name": "", "content": UNRELATED, "ttl": 3600, "priority": null, "weight": null, "port": null}),
	])
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let writes = writes(&state);
	// Each old SPF record was either edited (PATCH to /records/{id})
	// or deleted (DELETE to /records/{id}). Leaving either at the
	// spot is the bug the contract closes.
	let rec1_touched = writes.iter().any(|w| {
		w.ends_with("/records/1") && (w.starts_with("PATCH ") || w.starts_with("DELETE "))
	});
	let rec2_touched = writes.iter().any(|w| {
		w.ends_with("/records/2") && (w.starts_with("PATCH ") || w.starts_with("DELETE "))
	});
	assert!(
		rec1_touched,
		"old SPF1 was not edited or deleted: {writes:?}"
	);
	assert!(
		rec2_touched,
		"old SPF2 was left in place: {writes:?}"
	);
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
		fresh, 1,
		"exactly one SPF write carries the new value, bodies: {:?}",
		state.lock().unwrap().bodies
	);
	// The unrelated TXT must not be deleted.
	assert!(
		!writes
			.iter()
			.any(|w| w.ends_with("/records/3") && w.starts_with("DELETE ")),
		"the unrelated TXT was deleted: {writes:?}"
	);
}