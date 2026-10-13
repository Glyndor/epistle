//! The upsert contract against the Route 53 mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! A Route 53 UPSERT replaces the whole rrset, so it has to carry the
//! siblings it read.

use super::tests::mock;
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
