//! TXT encoding against the Route 53 mock: what each fixture puts in
//! `<Value>`, and the publish, read and compare round trip. Route 53's
//! `list` is unsupported, so the read side is the rrset fetch the
//! value-bearing delete uses.

use super::tests::mock;
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, SPECIAL_PRESENTATION, all, dkim_rsa2048,
	dkim_rsa2048_presentation,
};
use crate::dns::txt::same_txt_value;

fn txt(value: &str) -> DnsRecord {
	DnsRecord {
		name: "sel._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: value.into(),
		ttl: 3600,
	}
}

/// The raw text of every `<Value>` in `body`, still XML-escaped.
fn values(body: &str) -> Vec<String> {
	body.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect()
}

/// The `<Value>` the upsert sent, XML-escaped as it went on the wire.
async fn upsert_value(value: &str) -> String {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	let mut found = values(&body);
	assert_eq!(found.len(), 1, "{body}");
	found.remove(0)
}

#[tokio::test]
async fn txt_short_value_is_one_quoted_string() {
	assert_eq!(upsert_value(SHORT).await, format!("\"{SHORT}\""));
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_two_quoted_strings_in_one_value() {
	assert_eq!(
		upsert_value(&dkim_rsa2048()).await,
		dkim_rsa2048_presentation()
	);
}

#[tokio::test]
async fn txt_quote_and_backslash_are_escaped() {
	assert_eq!(
		upsert_value(SPECIAL).await,
		SPECIAL_PRESENTATION.replace('&', "&amp;")
	);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_not_quoted_twice() {
	assert_eq!(
		upsert_value(CALLER_QUOTED).await,
		format!("\"{CALLER_QUOTED_LOGICAL}\"")
	);
}

/// The `<Value>` the upsert sent is what a later read returns. The read
/// side has to give back the logical value, and a delete by the logical
/// value has to find the stored record and nothing else.
#[tokio::test]
async fn txt_publish_read_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = upsert_value(&value).await;
		let xml = format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListResourceRecordSetsResult><ResourceRecordSets><ResourceRecordSet>\
<Name>sel._domainkey.example.org.</Name><Type>TXT</Type><TTL>3600</TTL>\
<ResourceRecords>\
<ResourceRecord><Value>{stored}</Value></ResourceRecord>\
<ResourceRecord><Value>\"token-sibling\"</Value></ResourceRecord>\
</ResourceRecords></ResourceRecordSet></ResourceRecordSets>\
</ListResourceRecordSetsResult>"
		);
		let rrset = parse_txt_rrset(&xml, "sel._domainkey.example.org").expect("rrset");
		let read: Vec<String> = rrset.values.iter().map(|v| txt_read(v)).collect();
		assert_eq!(read[0], logical, "read value of {value}");
		assert!(same_txt_value(&read[0], &value), "{value}");
		let (provider, state) = mock().await;
		state.lock().unwrap().list_response = Some(xml);
		provider
			.delete("example.org", txt(&logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		let body = s.bodies.last().expect("a change was sent");
		assert_eq!(
			values(body),
			vec!["\"token-sibling\"".to_string()],
			"delete by the logical value must drop only {value}"
		);
	}
}
