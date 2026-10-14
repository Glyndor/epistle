//! TXT encoding against the OVH mock: what each fixture puts in `target`,
//! and the publish, list and compare round trip.

use super::tests::{StoredRecord, mock, mock_with};
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::{same_txt_value, txt_presentation};

const NAME: &str = "sel._domainkey.example.org";

fn txt(value: &str) -> DnsRecord {
	DnsRecord {
		name: NAME.into(),
		kind: RecordKind::Txt,
		value: value.into(),
		ttl: 3600,
		proxied: None,
	}
}

/// The `target` of the record the upsert created.
async fn sent(value: &str) -> String {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().write_body).expect("JSON body");
	body["target"].as_str().expect("target").to_string()
}

#[tokio::test]
async fn txt_short_value_is_sent_unquoted() {
	assert_eq!(sent(SHORT).await, SHORT);
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_sent_whole_and_unquoted() {
	assert_eq!(sent(&dkim_rsa2048()).await, dkim_rsa2048());
}

#[tokio::test]
async fn txt_quote_and_backslash_are_sent_as_they_are() {
	assert_eq!(sent(SPECIAL).await, SPECIAL);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_sent_without_the_quotes() {
	assert_eq!(sent(CALLER_QUOTED).await, CALLER_QUOTED_LOGICAL);
}

/// OVH hands a plain TXT target back in presentation form, quoted and cut
/// into 255-octet strings. Listing gives the logical value back, a second
/// publish updates the same record, and a delete by the logical value
/// removes it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = StoredRecord {
			id: 7,
			field_type: "TXT".into(),
			sub_domain: "sel._domainkey".into(),
			target: txt_presentation(&sent(&value).await),
			ttl: 3600,
		};
		let (provider, state) = mock_with(vec![stored]).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.upsert("example.org", txt(&value))
			.await
			.expect("again");
		{
			let s = state.lock().unwrap();
			assert_eq!(s.write_method, "PUT", "{value}");
			assert_eq!(s.write_path, "/domain/zone/example.org/record/7");
			let body: serde_json::Value = serde_json::from_str(&s.write_body).unwrap();
			assert_eq!(body["target"], logical.as_str(), "{value}");
		}
		provider
			.delete("example.org", txt(&logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		assert_eq!(s.write_method, "DELETE", "{value}");
		assert!(s.records.is_empty(), "{value}");
	}
}
