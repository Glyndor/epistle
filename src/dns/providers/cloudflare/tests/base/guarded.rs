use super::*;
use crate::dns::publish::provider::{Change, Guard, Precondition, Receipt};

fn a(value: &str) -> DnsRecord {
	DnsRecord::new("mail.example.org", RecordKind::A, value, 300)
}

fn stored(id: &str, value: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id, "type": "A", "name": "mail.example.org",
		"content": value, "ttl": 300, "proxied": false
	})
}

/// A change at `mail.example.org`, planned against what `provider` lists
/// now. `plan` builds the set to write from the records listed, which carry
/// over exactly as they were read.
async fn change(
	provider: &CloudflareProvider,
	plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>,
) -> Change {
	let snapshot = provider.publish_snapshot("example.org").await.unwrap();
	let listed: Vec<DnsRecord> = snapshot.records.iter().map(|o| o.record.clone()).collect();
	Change {
		name: "mail.example.org".into(),
		kind: RecordKind::A,
		before: snapshot.records,
		after: plan(&listed),
		precondition: Precondition::Identity,
		operation_id: "epistle-publish-test".into(),
	}
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
async fn the_snapshot_carries_the_record_ids_and_says_it_checks() {
	let (provider, _state) = mock(vec![stored("own", "203.0.113.10")]).await;
	let snapshot = provider.publish_snapshot("example.org").await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	assert_eq!(snapshot.revision, None);
	assert_eq!(snapshot.records.len(), 1);
	assert_eq!(snapshot.records[0].identity.as_deref(), Some("own"));
}

#[tokio::test]
async fn a_record_added_after_the_listing_stops_the_write() {
	let (provider, state) = mock(vec![stored("own", "203.0.113.10")]).await;
	let change = change(&provider, |_| vec![a("203.0.113.11")]).await;
	state
		.lock()
		.unwrap()
		.records
		.push(stored("theirs", "203.0.113.99"));
	let receipt = provider.apply_guarded("example.org", change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(writes(&state), Vec::<String>::new());
}

#[tokio::test]
async fn a_record_replaced_after_the_listing_stops_the_write() {
	let (provider, state) = mock(vec![stored("own", "203.0.113.10")]).await;
	let change = change(&provider, |_| vec![a("203.0.113.11")]).await;
	// The same id now holds another value.
	state.lock().unwrap().records = vec![stored("own", "203.0.113.50")];
	let receipt = provider.apply_guarded("example.org", change).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(writes(&state), Vec::<String>::new());
}

#[tokio::test]
async fn an_update_touches_only_the_record_that_changes() {
	let (provider, state) = mock(vec![
		stored("kept", "203.0.113.20"),
		stored("own", "203.0.113.10"),
	])
	.await;
	let change = change(&provider, |held| vec![held[0].clone(), a("203.0.113.11")]).await;
	let receipt = provider.apply_guarded("example.org", change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&state), vec!["PUT /zones/zone123/dns_records/own"]);
	let body = state.lock().unwrap().last_body.clone().unwrap();
	assert!(body.contains("203.0.113.11"), "{body}");
}

#[tokio::test]
async fn a_new_record_is_created_and_nothing_else_is_written() {
	let (provider, state) = mock(vec![stored("kept", "203.0.113.20")]).await;
	let change = change(&provider, |held| vec![held[0].clone(), a("203.0.113.11")]).await;
	let receipt = provider.apply_guarded("example.org", change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&state), vec!["POST /dns_records"]);
}

#[tokio::test]
async fn a_removal_deletes_only_its_own_id() {
	let (provider, state) = mock(vec![
		stored("kept", "203.0.113.20"),
		stored("own", "203.0.113.10"),
	])
	.await;
	let change = change(&provider, |held| vec![held[0].clone()]).await;
	let receipt = provider.apply_guarded("example.org", change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(
		writes(&state),
		vec!["DELETE /zones/zone123/dns_records/own"]
	);
}

#[tokio::test]
async fn a_change_that_alters_nothing_writes_nothing() {
	let (provider, state) = mock(vec![stored("own", "203.0.113.10")]).await;
	let held = change(&provider, |held| held.to_vec()).await;
	let receipt = provider.apply_guarded("example.org", held).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&state), Vec::<String>::new());
}

#[tokio::test]
async fn a_change_outside_its_name_is_refused_before_any_write() {
	let (provider, state) = mock(vec![stored("own", "203.0.113.10")]).await;
	let other = DnsRecord::new("other.example.org", RecordKind::A, "203.0.113.11", 300);
	let change = change(&provider, |_| vec![other]).await;
	let receipt = provider.apply_guarded("example.org", change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert_eq!(writes(&state), Vec::<String>::new());
}
