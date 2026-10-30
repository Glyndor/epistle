//! TXT encoding against the GoDaddy mock: what each fixture puts in
//! `data`, and the publish, list and compare round trip.

use super::base::{mock, mock_with};
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;
use axum::http::Method;

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

/// The PUT bodies sent so far, parsed.
fn puts(state: &super::base::Shared) -> Vec<serde_json::Value> {
	state
		.lock()
		.unwrap()
		.calls
		.iter()
		.filter(|c| c.method == Method::PUT)
		.map(|c| serde_json::from_str(&c.body).expect("JSON body"))
		.collect()
}

/// The `data` of the one element the upsert PUT.
async fn sent(value: &str) -> String {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt(value))
		.await
		.expect("upsert");
	puts(&state)[0][0]["data"]
		.as_str()
		.expect("data")
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

/// The mock keeps the set each PUT wrote. Listing gives the logical value
/// back, a second publish (as the caller had it, or as the list returned
/// it) PUTs the same one-element set again, and a delete by the logical
/// value removes the set.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = sent(&value).await;
		let zone = serde_json::json!([
			{ "type": "TXT", "name": "sel._domainkey", "data": stored, "ttl": 3600 }
		]);
		let (provider, state) = mock_with(zone).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		for again in [value.as_str(), logical.as_str(), CALLER_QUOTED] {
			if same_txt_value(again, &value) {
				provider
					.upsert("example.org", txt(again))
					.await
					.expect("again");
			}
		}
		let sets = puts(&state);
		assert!(
			sets.iter().all(|set| set.as_array().unwrap().len() == 1),
			"a republish must not add a second element: {value}"
		);
		assert!(sets.iter().all(|set| set[0]["data"] == stored), "{value}");
		provider
			.delete("example.org", txt(&logical))
			.await
			.expect("delete");
		let last = state.lock().unwrap().calls.last().unwrap().method.clone();
		assert_eq!(last, Method::DELETE, "{value}");
	}
}
