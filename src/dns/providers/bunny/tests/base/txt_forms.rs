//! TXT encoding against the Bunny mock: what each fixture puts in `Value`,
//! and the publish, list and compare round trip.

use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;

const NAME: &str = "sel._domainkey.example.org";

/// The `Value` of the record the upsert created.
async fn sent(value: &str) -> String {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt(NAME, value))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON body");
	body["Value"].as_str().expect("Value").to_string()
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

/// Bunny lists `Value` the way it was written. Listing gives the logical
/// value back, a second publish updates the same record with the same
/// bytes, and a delete by the logical value removes it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = sent(&value).await;
		let (provider, state) = mock().await;
		state.lock().unwrap().zone_detail = serde_json::json!({
			"Id": 42,
			"Records": [
				{ "Id": 7, "Type": 3, "Name": "sel._domainkey", "Value": stored, "Ttl": 3600 }
			]
		});
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.upsert("example.org", txt(NAME, &value))
			.await
			.expect("again");
		provider
			.delete("example.org", txt(NAME, &logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		let writes: Vec<&String> = s.calls.iter().filter(|c| !c.starts_with("GET")).collect();
		assert_eq!(
			writes,
			vec!["POST /dnszone/42/records/7", "DELETE /dnszone/42/records/7"],
			"{value}"
		);
		let again: serde_json::Value = serde_json::from_str(&s.bodies[0]).expect("JSON");
		assert_eq!(
			again["Value"], stored,
			"the rewrite is byte-identical: {value}"
		);
	}
}
