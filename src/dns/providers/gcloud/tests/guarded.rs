//! The guarded write of the Google Cloud DNS provider, against a mock that
//! applies a change as the API does: atomically, refusing a deletion that
//! does not match the live record set exactly (412) and an addition that
//! collides with one that stays (409).

use super::test_support::*;
use super::*;
use crate::dns::publish::provider::{Change, Guard, Precondition, Receipt};

const ZONE: &str = "example.org";
const NAME: &str = "mail.example.org";

fn a_set(addresses: &[&str]) -> Rrset {
	Rrset {
		name: "mail.example.org.".into(),
		kind: "A".into(),
		ttl: 300,
		rrdatas: addresses.iter().map(|a| a.to_string()).collect(),
	}
}

/// The zone of a case: the set under test, a set at another name and a TXT
/// at the same one. A change must leave the other two alone.
fn zone_with(addresses: &[&str]) -> Vec<Rrset> {
	let mut rrsets = vec![
		Rrset {
			name: "other.example.org.".into(),
			kind: "A".into(),
			ttl: 300,
			rrdatas: vec!["198.51.100.1".into()],
		},
		Rrset {
			name: "mail.example.org.".into(),
			kind: "TXT".into(),
			ttl: 300,
			rrdatas: vec!["\"v=spf1 -all\"".into()],
		},
	];
	if !addresses.is_empty() {
		rrsets.push(a_set(addresses));
	}
	rrsets
}

fn a(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::A, value, 300)
}

fn live_a(state: &Shared) -> Vec<String> {
	let s = state.lock().unwrap();
	let mut live: Vec<String> = s
		.live_rrsets
		.iter()
		.filter(|r| r.name == "mail.example.org." && r.kind == "A")
		.flat_map(|r| r.rrdatas.clone())
		.collect();
	live.sort();
	live
}

/// A change planned against what the provider lists now.
async fn change(
	provider: &GcloudProvider,
	precondition: Precondition,
	plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>,
) -> Change {
	let snapshot = provider.publish_snapshot(ZONE).await.unwrap();
	let before: Vec<_> = snapshot
		.records
		.into_iter()
		.filter(|o| o.record.name == NAME && o.record.kind == RecordKind::A)
		.collect();
	let listed: Vec<DnsRecord> = before.iter().map(|o| o.record.clone()).collect();
	Change {
		name: NAME.into(),
		kind: RecordKind::A,
		before,
		after: plan(&listed),
		precondition,
		operation_id: "epistle-publish-test".into(),
	}
}

#[tokio::test]
async fn the_snapshot_says_it_checks_and_lists_every_record() {
	let (base, _state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let snapshot = provider.publish_snapshot(ZONE).await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	assert_eq!(snapshot.revision, None);
	assert!(
		snapshot
			.records
			.iter()
			.any(|o| o.record == a("203.0.113.10"))
	);
	assert_eq!(snapshot.records.len(), 3);
}

#[tokio::test]
async fn a_value_added_after_the_listing_stops_the_write() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	state.lock().unwrap().live_rrsets = zone_with(&["203.0.113.10", "203.0.113.99"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.10", "203.0.113.99"]);
	assert!(state.lock().unwrap().changes.is_empty());
}

#[tokio::test]
async fn a_value_replaced_after_the_listing_stops_the_write() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	state.lock().unwrap().live_rrsets = zone_with(&["203.0.113.50"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.50"]);
}

#[tokio::test]
async fn a_set_that_appeared_where_the_plan_saw_none_stops_the_write() {
	let (base, state) = start_mock(zone_with(&[])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Absent, |_| vec![a("203.0.113.11")]).await;
	state.lock().unwrap().live_rrsets = zone_with(&["203.0.113.99"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.99"]);
}

/// The change another account makes after the provider read the set and
/// before its change arrives, which only the API can see: the deletion no
/// longer matches the live set and Cloud DNS refuses it.
#[tokio::test]
async fn a_set_changed_between_the_read_and_the_change_is_refused_by_the_api() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	state.lock().unwrap().race = Some(zone_with(&["203.0.113.10", "203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.10", "203.0.113.99"]);
}

#[tokio::test]
async fn a_set_created_between_the_read_and_the_change_is_refused_by_the_api() {
	let (base, state) = start_mock(zone_with(&[])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Absent, |_| vec![a("203.0.113.11")]).await;
	state.lock().unwrap().race = Some(zone_with(&["203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.99"]);
}

#[tokio::test]
async fn a_removal_after_a_race_leaves_the_value_another_account_added() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |_| Vec::new()).await;
	state.lock().unwrap().race = Some(zone_with(&["203.0.113.10", "203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&state), ["203.0.113.10", "203.0.113.99"]);
}

#[tokio::test]
async fn a_replacement_deletes_the_set_as_read_and_adds_the_new_one_in_one_change() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	let s = state.lock().unwrap();
	assert_eq!(s.changes.len(), 1, "one change");
	let body: Value = serde_json::from_str(&s.changes[0]).unwrap();
	assert_eq!(body["deletions"][0]["rrdatas"][0], "203.0.113.10");
	assert_eq!(body["additions"][0]["rrdatas"][0], "203.0.113.11");
	drop(s);
	assert_eq!(live_a(&state), ["203.0.113.11"]);
	// The set at another name and the TXT at the same one are untouched.
	let s = state.lock().unwrap();
	assert!(s.live_rrsets.iter().any(|r| r.name == "other.example.org."));
	assert!(s.live_rrsets.iter().any(|r| r.kind == "TXT"));
}

#[tokio::test]
async fn a_change_that_alters_nothing_posts_nothing() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let change = change(&provider, Precondition::Identity, |held| held.to_vec()).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert!(state.lock().unwrap().changes.is_empty());
}

#[tokio::test]
async fn a_change_outside_its_name_is_refused_before_anything_is_read() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10"])).await;
	let provider = provider_for(&base);
	let other = DnsRecord::new("other.example.org", RecordKind::A, "203.0.113.11", 300);
	let change = change(&provider, Precondition::Identity, |_| vec![other]).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert!(state.lock().unwrap().changes.is_empty());
}

#[tokio::test]
async fn an_exact_delete_removes_one_value_of_any_type() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10", "203.0.113.20"])).await;
	let provider = provider_for(&base);
	provider
		.delete_exact(ZONE, a("203.0.113.10"))
		.await
		.expect("exact delete");
	assert_eq!(live_a(&state), ["203.0.113.20"]);
}

#[tokio::test]
async fn an_exact_delete_after_a_race_loses_nothing_that_was_added() {
	let (base, state) = start_mock(zone_with(&["203.0.113.10", "203.0.113.20"])).await;
	let provider = provider_for(&base);
	state.lock().unwrap().race = Some(zone_with(&["203.0.113.10", "203.0.113.20", "203.0.113.99"]));
	assert!(
		provider
			.delete_exact(ZONE, a("203.0.113.10"))
			.await
			.is_err()
	);
	assert_eq!(
		live_a(&state),
		["203.0.113.10", "203.0.113.20", "203.0.113.99"]
	);
}

#[tokio::test]
async fn an_exact_delete_of_a_value_that_is_not_there_writes_nothing() {
	let (base, state) = start_mock(zone_with(&["203.0.113.20"])).await;
	let provider = provider_for(&base);
	provider
		.delete_exact(ZONE, a("203.0.113.10"))
		.await
		.expect("idempotent");
	assert!(state.lock().unwrap().changes.is_empty());
}
