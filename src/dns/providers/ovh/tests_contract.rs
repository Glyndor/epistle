//! The upsert contract against the OVH mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name
//! alone. Two records of the same purpose at the same name are a
//! configuration mistake (SPF returns `permerror`, RFC 7208 §4.5;
//! DMARC is ignored, RFC 7489 §6.6.3), so the upsert collapses them
//! into one carrying the new value. A zone that starts with two
//! `v=spf1` TXT plus one unrelated TXT ends with exactly one SPF TXT
//! (epistle's value) and the unrelated TXT untouched.

use super::tests::{StoredRecord, mock_with, txt};
use super::*;

fn apex_spf(id: u64, target: &str) -> StoredRecord {
	StoredRecord {
		id,
		field_type: "TXT".into(),
		sub_domain: "".into(),
		target: target.into(),
		ttl: 3600,
	}
}

#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (provider, state) = mock_with(vec![
		apex_spf(1, OLD_SPF_1),
		apex_spf(2, OLD_SPF_2),
		apex_spf(3, UNRELATED),
	])
	.await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	// The OVH mock mutates `records` on every write, so the live
	// zone state is the source of truth.
	let s = state.lock().unwrap();
	let spf: Vec<&StoredRecord> = s
		.records
		.iter()
		.filter(|r| r.field_type == "TXT" && r.sub_domain.is_empty())
		.collect();
	assert_eq!(
		spf.len(),
		2,
		"exactly one SPF + one unrelated TXT after the upsert, got {} records",
		spf.len()
	);
	let values: Vec<&str> = spf.iter().map(|r| r.target.as_str()).collect();
	assert!(
		values.contains(&NEW_SPF),
		"new SPF present in the zone: {values:?}"
	);
	assert!(
		!values.contains(&OLD_SPF_1),
		"old SPF1 was re-published: {values:?}"
	);
	assert!(
		!values.contains(&OLD_SPF_2),
		"old SPF2 was re-published: {values:?}"
	);
	assert!(
		values.contains(&UNRELATED),
		"the unrelated TXT was lost: {values:?}"
	);
}
