//! TXT encoding against the DNSimple mock: what each fixture puts in
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
		.upsert(ZONE, txt(NAME, value))
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

/// DNSimple keeps quoted content verbatim, and the mock keeps what the
/// create sent. Listing gives the logical value back, a second publish
/// updates the same record with the same bytes, and a delete by the logical
/// value removes it.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let (provider, state) = mock(Vec::new()).await;
		provider
			.upsert(ZONE, txt(NAME, &value))
			.await
			.expect("upsert");
		let listed = provider.list(ZONE).await.expect("list");
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider
			.upsert(ZONE, txt(NAME, &value))
			.await
			.expect("again");
		provider
			.delete(ZONE, txt(NAME, &logical))
			.await
			.expect("delete");
		let s = state.lock().unwrap();
		let writes: Vec<&String> = s.calls.iter().filter(|c| !c.starts_with("GET")).collect();
		assert_eq!(
			writes,
			vec![
				&format!("POST {PATH_BASE}"),
				&format!("PATCH {PATH_BASE}/1"),
				&format!("DELETE {PATH_BASE}/1"),
			],
			"{value}"
		);
		assert_eq!(
			s.bodies[0], s.bodies[1],
			"the rewrite is byte-identical: {value}"
		);
	}
}
