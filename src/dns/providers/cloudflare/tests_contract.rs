//! The upsert contract for kinds other than TXT against the Cloudflare
//! mock: epistle owns an A or AAAA name and a write replaces the whole set
//! (`src/dns/provider.rs`), so a new address updates the record in place
//! instead of adding a second one.

use super::*;
use crate::dns::providers::listing_contract::{
	CAA_VALUE, HOSTILE_TYPE, HTTPS_VALUE, NAPTR_VALUE, NS_TARGET, OPAQUE_VALUE, SVCB_VALUE, Shape,
	assert_kinds_kept,
};

fn address(kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord {
		name: "mail.example.org".into(),
		kind,
		value: value.into(),
		ttl: 3600,
		proxied: None,
	}
}

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
		proxied: None,
	}
}

fn stored(id: &str, kind: &str, content: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id, "type": kind, "name": "mail.example.org", "content": content, "ttl": 3600
	})
}

fn stored_at(name: &str, id: &str, kind: &str, content: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id, "type": kind, "name": name, "content": content, "ttl": 3600
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
async fn a_new_address_updates_the_existing_a_record() {
	let (provider, state) = mock(vec![stored("rec1", "A", "192.0.2.1")]).await;
	provider
		.upsert("example.org", address(RecordKind::A, "192.0.2.2"))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["PUT /zones/zone123/dns_records/rec1"]);
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON");
	assert_eq!(body["content"], "192.0.2.2");
}

#[tokio::test]
async fn a_new_address_updates_the_existing_aaaa_record() {
	let (provider, state) = mock(vec![stored("rec1", "AAAA", "2001:db8::1")]).await;
	provider
		.upsert("example.org", address(RecordKind::Aaaa, "2001:db8::2"))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["PUT /zones/zone123/dns_records/rec1"]);
}

/// A name that already holds two A records (written by hand, or by an
/// older release) ends with the one record the upsert carries.
#[tokio::test]
async fn an_upsert_collapses_an_existing_a_set_to_one_record() {
	let (provider, state) = mock(vec![
		stored("rec1", "A", "192.0.2.1"),
		stored("rec2", "A", "192.0.2.9"),
	])
	.await;
	provider
		.upsert("example.org", address(RecordKind::A, "192.0.2.2"))
		.await
		.expect("upsert");
	assert_eq!(
		writes(&state),
		vec![
			"PUT /zones/zone123/dns_records/rec1",
			"DELETE /zones/zone123/dns_records/rec2"
		]
	);
}

/// Two SPF TXT records at the same name (an apex is the canonical case)
/// plus one unrelated TXT is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a third
/// record. A naive find-first-match implementation would update record 1
/// and leave record 2 in place, the bug the contract is closing.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (provider, state) = mock(vec![
		stored_at("example.org", "rec1", "TXT", OLD_SPF_1),
		stored_at("example.org", "rec2", "TXT", OLD_SPF_2),
		stored_at("example.org", "rec3", "TXT", UNRELATED),
	])
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let writes = writes(&state);
	// Each old SPF record must have been removed from the wire
	// trace: either edited in place (PUT to /records/{id}) or deleted
	// (DELETE to /records/{id}). Leaving either record at the spot is
	// the bug the contract closes: a second SPF at the same name makes
	// every receiver return SPF permerror.
	let rec1_touched = writes.iter().any(|w| {
		w == "PUT /zones/zone123/dns_records/rec1" || w == "DELETE /zones/zone123/dns_records/rec1"
	});
	let rec2_touched = writes.iter().any(|w| {
		w == "PUT /zones/zone123/dns_records/rec2" || w == "DELETE /zones/zone123/dns_records/rec2"
	});
	assert!(
		rec1_touched,
		"old SPF1 was not edited or deleted: {writes:?}"
	);
	assert!(rec2_touched, "old SPF2 was left in place: {writes:?}");
	// No write carries an old SPF value. The Cloudflare wire payload
	// is JSON with the TXT in presentation form, so the on-wire
	// substring for "v=spf1 mx -all" is the bare logical value
	// escaped into a JSON string. Matching the unique tail of each
	// old value avoids ambiguity with the new one.
	for body in &state.lock().unwrap().bodies {
		assert!(
			!body.contains("mx -all"),
			"old SPF1 (mx -all) was re-published: {body}"
		);
		assert!(
			!body.contains("_spf.google.com"),
			"old SPF2 (include _spf.google.com) was re-published: {body}"
		);
	}
	// Exactly one write carries the new SPF value.
	let fresh = state
		.lock()
		.unwrap()
		.bodies
		.iter()
		.filter(|b| b.contains("v=spf1 -all"))
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
			.any(|w| w == "DELETE /zones/zone123/dns_records/rec3"),
		"the unrelated TXT was deleted: {writes:?}"
	);
}

/// A zone with a delegated subdomain and records of types epistle does not
/// publish lists every one of them with its own kind: nothing is turned into
/// a TXT, and a type token that is not a record type comes back as
/// `UNKNOWN`.
#[tokio::test]
async fn list_keeps_ns_caa_https_svcb_and_unknown_kinds() {
	let hostile = HOSTILE_TYPE;
	let (provider, _state) = mock(vec![
		stored_at("sub.example.org", "1", "NS", NS_TARGET),
		stored_at("example.org", "2", "CAA", CAA_VALUE),
		stored_at("example.org", "3", "HTTPS", HTTPS_VALUE),
		stored_at("example.org", "4", "SVCB", SVCB_VALUE),
		stored_at("example.org", "5", "NAPTR", NAPTR_VALUE),
		stored_at("example.org", "6", hostile, OPAQUE_VALUE),
	])
	.await;
	let listed = provider.list("example.org").await.expect("list");
	assert_kinds_kept(&listed, &Shape::NAMED);
}

/// Kinds a listing shows but epistle does not publish are never written
/// or removed.
#[tokio::test]
async fn listed_only_kinds_are_never_written() {
	let (provider, _state) = mock(Vec::new()).await;
	crate::dns::providers::listing_contract::assert_listed_kinds_are_not_written(&provider).await;
}

/// A zone with more records than a listing reads is an error, not a zone cut
/// short.
#[tokio::test]
async fn a_zone_past_the_record_cap_is_an_error() {
	let record = stored_at("h.example.org", "1", "A", "192.0.2.1");
	let (provider, state) = mock(vec![record; 100_001]).await;
	state.lock().unwrap().total_pages = Some(1);
	let error = provider.list("example.org").await.expect_err("too many");
	assert_eq!(
		error,
		ProviderError::Remote(crate::dns::providers::listing_contract::CAP_MESSAGE.to_string())
	);
}

/// An answer without its page count is not the last page: a full page may be
/// followed by more, and reading it as the whole zone would hide the rest.
/// A short page is the last one, count or no count.
#[tokio::test]
async fn a_full_page_without_a_page_count_is_an_error() {
	let record = stored_at("h.example.org", "1", "A", "192.0.2.1");
	let (provider, _state) = mock(vec![record.clone(); 100]).await;
	let error = provider.list("example.org").await.expect_err("full page");
	assert_eq!(
		error,
		ProviderError::Remote(
			"the example.org listing does not say how many pages there are".to_string()
		)
	);
	let (provider, _state) = mock(vec![record; 99]).await;
	assert_eq!(
		provider
			.list("example.org")
			.await
			.expect("short page")
			.len(),
		99
	);
}
