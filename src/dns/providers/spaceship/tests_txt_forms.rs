//! TXT encoding against the Spaceship mock: what each fixture puts in
//! `value`, and the publish, list and compare round trip.

use super::tests::mock;
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

/// The `value` the upsert saved. With nothing at the name there is no
/// old record to delete first.
async fn sent(value: &str) -> String {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.bodies.len(), 1, "only the save: {:?}", s.bodies);
	let saved: serde_json::Value = serde_json::from_str(&s.bodies[0]).expect("JSON");
	saved["items"][0]["value"]
		.as_str()
		.expect("value")
		.to_string()
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

/// Spaceship deletes a TXT by its exact value. Listing gives the logical
/// value back, and both the delete that clears the way for a second publish
/// and a delete by the logical value name exactly the value that was
/// stored, so neither leaves a duplicate behind. The bodies are: save,
/// then delete and save for the second publish, then the delete.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let (provider, state) = mock(Vec::new()).await;
		provider
			.upsert("example.org", txt(&value))
			.await
			.expect("upsert");
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		let stored = state.lock().unwrap().records.values().next().unwrap()["value"].clone();
		provider
			.upsert("example.org", txt(&value))
			.await
			.expect("again");
		provider
			.delete("example.org", txt(&logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		let deletes: Vec<serde_json::Value> = [1, 3]
			.iter()
			.map(|i| {
				serde_json::from_str::<serde_json::Value>(&s.bodies[*i]).unwrap()[0]["value"]
					.clone()
			})
			.collect();
		assert_eq!(deletes, vec![stored.clone(), stored], "{value}");
	}
}
