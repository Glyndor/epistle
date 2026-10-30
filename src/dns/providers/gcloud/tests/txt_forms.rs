//! TXT encoding against the Cloud DNS mock: what each fixture puts in
//! `rrdatas`, and the publish, list and compare round trip.

use super::test_support::*;
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, SPECIAL_PRESENTATION, all, dkim_rsa2048,
	dkim_rsa2048_presentation,
};
use crate::dns::txt::same_txt_value;

/// The `rrdatas` of the first addition in the last change body.
fn added_rrdatas(body: &str) -> Vec<String> {
	let change: serde_json::Value = serde_json::from_str(body).expect("change body is JSON");
	change["additions"][0]["rrdatas"]
		.as_array()
		.expect("rrdatas array")
		.iter()
		.map(|r| r.as_str().expect("string rdata").to_string())
		.collect()
}

async fn upsert_rrdatas(value: &str) -> Vec<String> {
	let (base, state) = start_mock(Vec::new()).await;
	provider_for(&base)
		.upsert("example.org", txt("sel._domainkey.example.org", value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	added_rrdatas(&body)
}

#[tokio::test]
async fn txt_short_value_is_one_quoted_string() {
	assert_eq!(upsert_rrdatas(SHORT).await, vec![format!("\"{SHORT}\"")]);
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_two_quoted_strings_in_one_rdata() {
	assert_eq!(
		upsert_rrdatas(&dkim_rsa2048()).await,
		vec![dkim_rsa2048_presentation()]
	);
}

#[tokio::test]
async fn txt_quote_and_backslash_are_escaped() {
	assert_eq!(
		upsert_rrdatas(SPECIAL).await,
		vec![SPECIAL_PRESENTATION.to_string()]
	);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_not_quoted_twice() {
	assert_eq!(
		upsert_rrdatas(CALLER_QUOTED).await,
		vec![format!("\"{CALLER_QUOTED_LOGICAL}\"")]
	);
}

/// The mock keeps what the change added: listing gives the logical value
/// back, and publishing the same value again (as the caller had it, or as
/// the list returned it) sends no second change.
#[tokio::test]
async fn txt_publish_list_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let (base, state) = start_mock(Vec::new()).await;
		let provider = provider_for(&base);
		let record = txt("sel._domainkey.example.org", &value);
		provider
			.upsert("example.org", record.clone())
			.await
			.expect("upsert");
		let listed = provider.list("example.org").await.expect("list");
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].value, logical, "listed value of {value}");
		assert!(same_txt_value(&listed[0].value, &value), "{value}");
		provider.upsert("example.org", record).await.expect("again");
		provider
			.upsert("example.org", listed[0].clone())
			.await
			.expect("listed form");
		assert_eq!(
			state.lock().unwrap().changes.len(),
			1,
			"an unchanged value must not be written again: {value}"
		);
	}
}

/// Cloud DNS may hand a long value back with its strings run together
/// (`"a""b"`); that is the same record, not a change.
#[tokio::test]
async fn txt_a_differently_spaced_listing_is_not_a_change() {
	let value = dkim_rsa2048();
	let stored = format!("\"{}\"\"{}\"", &value[..255], &value[255..]);
	let (base, state) = start_mock(vec![Rrset {
		name: "sel._domainkey.example.org.".into(),
		kind: "TXT".into(),
		ttl: 3600,
		rrdatas: vec![stored],
	}])
	.await;
	provider_for(&base)
		.upsert("example.org", txt("sel._domainkey.example.org", &value))
		.await
		.expect("upsert");
	assert!(state.lock().unwrap().changes.is_empty());
}
