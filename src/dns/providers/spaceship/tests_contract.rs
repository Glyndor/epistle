//! The upsert contract against the Spaceship mock: a TXT upsert replaces the
//! record of the same purpose and leaves every other TXT at the name alone.
//! Spaceship deletes a TXT by its exact value, so the upsert has to name the
//! OLD value of that purpose, never the new one.

use super::tests::mock;
use super::*;
use crate::dns::txt::fixtures::{NEW_DKIM, OLD_DKIM, SIBLING};

fn txt(value: &str) -> DnsRecord {
	DnsRecord {
		name: "sel._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: value.into(),
		ttl: 3600,
	}
}

fn stored(value: &str) -> serde_json::Value {
	serde_json::json!({"type": "TXT", "name": "sel._domainkey", "value": value, "ttl": 3600})
}

/// The values every DELETE named, and the values every save added.
async fn upsert_over(existing: &[&str]) -> (Vec<String>, Vec<String>) {
	let (provider, state) = mock(existing.iter().map(|v| stored(v)).collect()).await;
	provider
		.upsert("example.org", txt(NEW_DKIM))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let writes = s.calls.iter().filter(|c| !c.starts_with("GET"));
	let (mut deleted, mut saved) = (Vec::new(), Vec::new());
	for (call, body) in writes.zip(&s.bodies) {
		let body: serde_json::Value = serde_json::from_str(body).expect("JSON");
		if call.starts_with("DELETE") {
			for item in body.as_array().expect("array") {
				deleted.push(item["value"].as_str().unwrap_or("<wholesale>").to_string());
			}
		} else {
			for item in body["items"].as_array().expect("items") {
				saved.push(item["value"].as_str().expect("value").to_string());
			}
		}
	}
	(deleted, saved)
}

#[tokio::test]
async fn txt_upsert_keeps_a_sibling_of_another_purpose() {
	let (deleted, saved) = upsert_over(&[SIBLING]).await;
	assert!(!deleted.iter().any(|v| v == SIBLING), "{deleted:?}");
	assert!(!deleted.iter().any(|v| v == "<wholesale>"), "{deleted:?}");
	assert_eq!(saved, vec![NEW_DKIM.to_string()]);
}

#[tokio::test]
async fn txt_rotation_leaves_one_record_of_that_purpose() {
	let (deleted, saved) = upsert_over(&[SIBLING, OLD_DKIM]).await;
	assert_eq!(deleted, vec![OLD_DKIM.to_string()]);
	assert_eq!(saved, vec![NEW_DKIM.to_string()]);
}
