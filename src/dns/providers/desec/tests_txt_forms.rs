//! TXT encoding against the deSEC mock: what each fixture puts in
//! `records`, and the publish, list and compare round trip.

use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, SPECIAL_PRESENTATION, all, dkim_rsa2048,
	dkim_rsa2048_presentation,
};
use crate::dns::txt::same_txt_value;

/// The `records` array of the one rrset in a captured PUT body.
fn put_records(body: &str) -> Vec<String> {
	let rrsets: serde_json::Value = serde_json::from_str(body).expect("PUT body is JSON");
	rrsets[0]["records"]
		.as_array()
		.expect("records array")
		.iter()
		.map(|r| r.as_str().expect("string record").to_string())
		.collect()
}

async fn upsert_records(value: &str) -> Vec<String> {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("sel._domainkey.example.org", value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	put_records(&body)
}

#[tokio::test]
async fn txt_short_value_is_one_quoted_string() {
	assert_eq!(upsert_records(SHORT).await, vec![format!("\"{SHORT}\"")]);
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_two_quoted_strings_in_one_record() {
	assert_eq!(
		upsert_records(&dkim_rsa2048()).await,
		vec![dkim_rsa2048_presentation()]
	);
}

#[tokio::test]
async fn txt_quote_and_backslash_are_escaped() {
	assert_eq!(
		upsert_records(SPECIAL).await,
		vec![SPECIAL_PRESENTATION.to_string()]
	);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_not_quoted_twice() {
	assert_eq!(
		upsert_records(CALLER_QUOTED).await,
		vec![format!("\"{CALLER_QUOTED_LOGICAL}\"")]
	);
}

/// What deSEC stores is what it lists, so the PUT body seeds the next
/// mock: listing gives the logical value back, the compare finds no
/// change, and a delete by the logical value finds the stored record.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let stored = upsert_records(&value).await;
		let rrsets = serde_json::json!([{
			"subname": "sel._domainkey",
			"type": "TXT",
			"ttl": 3600,
			"records": stored,
		}]);
		let (provider, state) = mock(rrsets).await;
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.delete(
				"example.org",
				txt("sel._domainkey.example.org", &listed[0].value),
			)
			.await
			.expect("delete");
		let body = state.lock().unwrap().puts[0].clone();
		assert!(
			put_records(&body).is_empty(),
			"delete by the listed value must find the record: {value}"
		);
	}
}
