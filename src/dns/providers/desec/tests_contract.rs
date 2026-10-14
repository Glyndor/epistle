//! The upsert contract against the deSEC mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! deSEC's bulk PUT replaces the whole rrset, so the upsert has to carry the
//! siblings it read.

use super::*;
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
