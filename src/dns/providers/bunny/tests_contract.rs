//! The upsert contract against the Bunny mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.

use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

const NAME: &str = "sel._domainkey.example.org";

/// A zone holding the sibling (id 1, listed first) and the old DKIM key
/// (id 2) at the same name.
async fn zone_with_sibling_and_old_key() -> (BunnyProvider, Shared) {
	let (provider, state) = mock().await;
	state.lock().unwrap().zone_detail = serde_json::json!({
		"Id": 42,
		"Records": [
			{ "Id": 1, "Type": 3, "Name": "sel._domainkey", "Value": SIBLING, "Ttl": 3600 },
			{ "Id": 2, "Type": 3, "Name": "sel._domainkey", "Value": OLD_DKIM, "Ttl": 3600 }
		]
	});
	(provider, state)
}

fn writes(state: &Shared) -> Vec<String> {
	state
		.lock()
		.unwrap()
		.calls
		.iter()
		.filter(|c| !c.starts_with("GET"))
		.cloned()
		.collect()
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert!(
		!writes(&state).iter().any(|w| w.ends_with("/records/1")),
		"the sibling was written over: {:?}",
		writes(&state)
	);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let (provider, state) = zone_with_sibling_and_old_key().await;
	provider
		.upsert("example.org", txt(NAME, NEW_DKIM))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["POST /dnszone/42/records/2"]);
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON");
	assert_eq!(body["Value"], NEW_DKIM);
}
