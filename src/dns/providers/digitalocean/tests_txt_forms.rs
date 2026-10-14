//! TXT encoding against the DigitalOcean mock: what each fixture puts in
//! `data`, and the publish, list and compare round trip.

use super::mock;
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;

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

/// The `data` field of the record the upsert created.
async fn sent(value: &str) -> String {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON body");
	body["data"].as_str().expect("data").to_string()
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

/// DigitalOcean lists `data` the way it was written. Listing gives the
/// logical value back, a second publish finds the same record instead of
/// creating another, and a delete by the logical value removes it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = sent(&value).await;
		let existing = serde_json::json!({
			"id": 7, "type": "TXT", "name": "sel._domainkey", "data": stored, "ttl": 3600,
		});
		let (provider, state) = mock(vec![existing], false).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.upsert("example.org", txt(&value))
			.await
			.expect("again");
		provider
			.delete("example.org", txt(&logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		let writes: Vec<&String> = s.calls.iter().filter(|c| !c.starts_with("GET")).collect();
		assert_eq!(
			writes,
			vec![
				"PUT /v2/domains/example.org/records/7",
				"DELETE /v2/domains/example.org/records/7"
			],
			"{value}"
		);
		let again: serde_json::Value = serde_json::from_str(&s.bodies[0]).expect("JSON");
		assert_eq!(
			again["data"], stored,
			"the rewrite is byte-identical: {value}"
		);
	}
}
