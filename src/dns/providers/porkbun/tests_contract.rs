//! The upsert contract against the Porkbun mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.

use super::*;
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
