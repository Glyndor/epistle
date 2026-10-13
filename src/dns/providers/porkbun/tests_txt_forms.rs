//! TXT encoding against the Porkbun mock: what each fixture puts in
//! `content`, and the publish, list and compare round trip.

use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;

const NAME: &str = "sel._domainkey.example.org";

/// The `content` of the record the upsert created.
async fn sent(value: &str) -> String {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt(NAME, value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().body("/dns/create/example.org");
	body["content"].as_str().expect("content").to_string()
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

/// Porkbun lists `content` the way it was written. Listing gives the
/// logical value back, a second publish edits the same record with the same
/// bytes, and a delete by the logical value removes it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let content = sent(&value).await;
		let (provider, state) = mock(serde_json::json!([stored("7", NAME, "TXT", &content)])).await;
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
		let writes: Vec<&str> = s
			.paths()
			.into_iter()
			.filter(|p| !p.starts_with("/dns/retrieve"))
			.collect();
		assert_eq!(
			writes,
			vec!["/dns/edit/example.org/7", "/dns/delete/example.org/7"],
			"{value}"
		);
		assert_eq!(
			s.body("/dns/edit/example.org/7")["content"],
			content,
			"the rewrite is byte-identical: {value}"
		);
	}
}
