//! The upsert contract against the Route 53 mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! A Route 53 UPSERT replaces the whole rrset, so it has to carry the
//! siblings it read.

use super::base::mock;
use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

fn rrset_xml(values: &[&str]) -> String {
	let records: String = values
		.iter()
		.map(|v| format!("<ResourceRecord><Value>\"{v}\"</Value></ResourceRecord>"))
		.collect();
	format!(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListResourceRecordSetsResult><ResourceRecordSets><ResourceRecordSet>\
<Name>{NAME}.</Name><Type>TXT</Type><TTL>3600</TTL>\
<ResourceRecords>{records}</ResourceRecords></ResourceRecordSet>\
</ResourceRecordSets><IsTruncated>false</IsTruncated>\
</ListResourceRecordSetsResult>"
	)
}

/// The `<Value>`s of the last change, sorted.
async fn upsert_over(existing: &[&str]) -> Vec<String> {
	let (provider, state) = mock().await;
	state.lock().unwrap().list_response = Some(rrset_xml(existing));
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: NAME.into(),
				kind: RecordKind::Txt,
				value: NEW_DKIM.into(),
				ttl: 3600,
				proxied: None,
			},
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body = s.bodies.last().expect("a change");
	assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
	let mut values: Vec<String> = body
		.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect();
	values.sort();
	values
}

fn quoted(v: &str) -> String {
	format!("\"{v}\"")
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let values = upsert_over(&[SIBLING]).await;
	assert!(values.contains(&quoted(SIBLING)), "{values:?}");
	assert!(values.contains(&quoted(NEW_DKIM)), "{values:?}");
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let values = upsert_over(&[SIBLING, OLD_DKIM]).await;
	let mut expected = vec![quoted(SIBLING), quoted(NEW_DKIM)];
	expected.sort();
	assert_eq!(values, expected);
}

/// Two SPF records at the same name plus one unrelated TXT (a site
/// verification token) is a configuration mistake every receiver turns
/// into a permanent error: SPF returns `permerror` (RFC 7208 §4.5).
/// The upsert must collapse the two SPF entries into one carrying the
/// new value, leave the unrelated TXT alone, and never create a
/// third record. Route 53 UPSERTs the whole rrset, so the test
/// checks the values of the rrset the final UPSERT wrote.
#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let initial = [OLD_SPF_1, OLD_SPF_2, UNRELATED];
	let (provider, state) = mock().await;
	state.lock().unwrap().list_response = Some(rrset_xml(&initial));
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: NAME.into(),
				kind: RecordKind::Txt,
				value: NEW_SPF.into(),
				ttl: 3600,
				proxied: None,
			},
		)
		.await
		.expect("apex SPF upsert with duplicates");
	let s = state.lock().unwrap();
	let body = s.bodies.last().expect("a change").clone();
	assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
	let mut values: Vec<String> = body
		.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect();
	values.sort();
	let mut want = vec![quoted(NEW_SPF), quoted(UNRELATED)];
	want.sort();
	assert_eq!(
		values, want,
		"the UPSERT body must carry exactly one SPF (new) and the unrelated TXT"
	);
}

/// Kinds a listing shows but epistle does not publish are never written
/// or removed.
#[tokio::test]
async fn listed_only_kinds_are_never_written() {
	let (provider, _state) = mock().await;
	crate::dns::providers::tests::listing_contract::assert_listed_kinds_are_not_written(&provider)
		.await;
}
