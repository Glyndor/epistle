//! The upsert contract against the Cloud DNS mock: a TXT upsert replaces
//! the record of the same purpose and leaves every other TXT at the name
//! alone. Cloud DNS changes a whole rrset at a time, so the upsert has to
//! carry the siblings it read.

use super::test_support::*;
use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};
use crate::dns::txt::txt_presentation;

async fn upsert_over(existing: &[&str]) -> Vec<String> {
	let (base, state) = start_mock(vec![Rrset {
		name: "sel._domainkey.example.org.".into(),
		kind: "TXT".into(),
		ttl: 3600,
		rrdatas: existing.iter().map(|v| txt_presentation(v)).collect(),
	}])
	.await;
	provider_for(&base)
		.upsert("example.org", txt("sel._domainkey.example.org", NEW_DKIM))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.live_rrsets.len(), 1, "one TXT rrset at the name");
	let mut live = s.live_rrsets[0].rrdatas.clone();
	live.sort();
	live
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let live = upsert_over(&[SIBLING]).await;
	assert!(live.contains(&txt_presentation(SIBLING)), "{live:?}");
	assert!(live.contains(&txt_presentation(NEW_DKIM)), "{live:?}");
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let live = upsert_over(&[SIBLING, OLD_DKIM]).await;
	let mut expected = vec![txt_presentation(SIBLING), txt_presentation(NEW_DKIM)];
	expected.sort();
	assert_eq!(live, expected);
}

/// Two SPF records at the apex plus one unrelated TXT (a site
/// verification token) is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a
/// third record.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let (base, state) = start_mock(vec![Rrset {
		name: "example.org.".into(),
		kind: "TXT".into(),
		ttl: 3600,
		rrdatas: [OLD_SPF_1, OLD_SPF_2, UNRELATED]
			.iter()
			.map(|v| txt_presentation(v))
			.collect(),
	}])
	.await;
	provider_for(&base)
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let s = state.lock().unwrap();
	let mut live: Vec<String> = s.live_rrsets[0].rrdatas.clone();
	live.sort();
	let new = txt_presentation(NEW_SPF);
	let unrelated = txt_presentation(UNRELATED);
	let mut expected = vec![unrelated, new];
	expected.sort();
	assert_eq!(
		live, expected,
		"the rrset must carry exactly one SPF (new) and the unrelated TXT"
	);
}
