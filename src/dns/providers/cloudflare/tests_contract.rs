//! The upsert contract for kinds other than TXT against the Cloudflare
//! mock: epistle owns an A or AAAA name and a write replaces the whole set
//! (`src/dns/provider.rs`), so a new address updates the record in place
//! instead of adding a second one.

use super::*;

fn address(kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord {
		name: "mail.example.org".into(),
		kind,
		value: value.into(),
		ttl: 3600,
	}
}

fn stored(id: &str, kind: &str, content: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id, "type": kind, "name": "mail.example.org", "content": content, "ttl": 3600
	})
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
async fn a_new_address_updates_the_existing_a_record() {
	let (provider, state) = mock(vec![stored("rec1", "A", "192.0.2.1")]).await;
	provider
		.upsert("example.org", address(RecordKind::A, "192.0.2.2"))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["PUT /zones/zone123/dns_records/rec1"]);
	let body: serde_json::Value =
		serde_json::from_str(&state.lock().unwrap().bodies[0]).expect("JSON");
	assert_eq!(body["content"], "192.0.2.2");
}

#[tokio::test]
async fn a_new_address_updates_the_existing_aaaa_record() {
	let (provider, state) = mock(vec![stored("rec1", "AAAA", "2001:db8::1")]).await;
	provider
		.upsert("example.org", address(RecordKind::Aaaa, "2001:db8::2"))
		.await
		.expect("upsert");
	assert_eq!(writes(&state), vec!["PUT /zones/zone123/dns_records/rec1"]);
}

/// A name that already holds two A records (written by hand, or by an
/// older release) ends with the one record the upsert carries.
#[tokio::test]
async fn an_upsert_collapses_an_existing_a_set_to_one_record() {
	let (provider, state) = mock(vec![
		stored("rec1", "A", "192.0.2.1"),
		stored("rec2", "A", "192.0.2.9"),
	])
	.await;
	provider
		.upsert("example.org", address(RecordKind::A, "192.0.2.2"))
		.await
		.expect("upsert");
	assert_eq!(
		writes(&state),
		vec![
			"PUT /zones/zone123/dns_records/rec1",
			"DELETE /zones/zone123/dns_records/rec2"
		]
	);
}
