//! TXT encoding against the Cloudflare mock: what each fixture puts in
//! `content`, and the publish, list and compare round trip.

use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, SPECIAL_PRESENTATION, all, dkim_rsa2048,
	dkim_rsa2048_presentation,
};
use crate::dns::txt::same_txt_value;

const NAME: &str = "sel._domainkey.example.org";

/// The `content` of the record the upsert created.
async fn sent(value: &str) -> String {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt(NAME, value))
		.await
		.expect("upsert");
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON body");
	body["content"].as_str().expect("content").to_string()
}

#[tokio::test]
async fn txt_short_value_is_one_quoted_string() {
	assert_eq!(sent(SHORT).await, format!("\"{SHORT}\""));
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_two_quoted_strings() {
	assert_eq!(sent(&dkim_rsa2048()).await, dkim_rsa2048_presentation());
}

#[tokio::test]
async fn txt_quote_and_backslash_are_escaped() {
	assert_eq!(sent(SPECIAL).await, SPECIAL_PRESENTATION);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_not_quoted_twice() {
	assert_eq!(
		sent(CALLER_QUOTED).await,
		format!("\"{CALLER_QUOTED_LOGICAL}\"")
	);
}

/// The stored `content` is what the next list returns. Listing gives the
/// logical value back, a second publish updates the same record with the
/// same bytes, and a delete by the logical value finds it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = sent(&value).await;
		let existing = vec![serde_json::json!({
			"id": "rec7", "type": "TXT", "name": NAME, "content": stored, "ttl": 3600
		})];
		let (provider, state) = mock(existing).await;
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
			vec![
				"PUT /zones/zone123/dns_records/rec7",
				"DELETE /zones/zone123/dns_records/rec7"
			],
			"{value}"
		);
		let again: serde_json::Value = serde_json::from_str(&s.bodies[0]).expect("JSON");
		assert_eq!(
			again["content"], stored,
			"the rewrite is byte-identical: {value}"
		);
	}
}

/// A record an older release wrote unquoted, and one Cloudflare re-chunked
/// with its strings run together, both read as the same logical value.
#[tokio::test]
async fn txt_unquoted_and_rechunked_listings_read_as_the_logical_value() {
	let value = dkim_rsa2048();
	let rechunked = format!("\"{}\"\"{}\"", &value[..200], &value[200..]);
	for stored in [value.clone(), rechunked] {
		let existing = vec![serde_json::json!({
			"id": "rec7", "type": "TXT", "name": NAME, "content": stored, "ttl": 3600
		})];
		let (provider, _state) = mock(existing).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed[0].value, value);
	}
}
