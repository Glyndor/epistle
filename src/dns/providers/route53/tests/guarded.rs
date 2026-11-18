//! The guarded write of the Route 53 provider, against a hosted zone that
//! applies a change batch as the API does (see `zone`).
//!
//! The shared `guarded_contract` is written for providers that address a
//! record by its id (`update <id>`, `delete <id>`). Route 53 has no record
//! ids: it replaces a record set by name and type in one batch. These are the
//! same cases in that shape, the way Google Cloud DNS tests them.

use super::zone::{Held, Set, apex, set, start};
use super::*;
use crate::dns::publish::provider::{Change, Guard, Precondition, Receipt};

const ZONE: &str = "example.org";
const NAME: &str = "mail.example.org";

/// The zone of a case: the apex, a set at another name, a TXT at the same
/// name and, unless empty, the A set under test. A change must leave every
/// other set alone.
fn zone_with(addresses: &[&str]) -> Vec<Set> {
	let mut sets = apex();
	sets.push(set("other.example.org.", "A", &["198.51.100.1"]));
	sets.push(set("mail.example.org.", "TXT", &["\"v=spf1 -all\""]));
	if !addresses.is_empty() {
		sets.push(set("mail.example.org.", "A", addresses));
	}
	sets
}

fn a(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::A, value, 300)
}

fn live_a(zone: &Held) -> Vec<String> {
	let mut live: Vec<String> = zone
		.lock()
		.unwrap()
		.sets
		.iter()
		.filter(|s| s.name == "mail.example.org." && s.kind == "A")
		.flat_map(|s| s.values.clone())
		.collect();
	live.sort();
	live
}

/// A change planned against what the provider lists now.
async fn change(
	provider: &Route53Provider,
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
	let (provider, _zone) = start(zone_with(&["203.0.113.10"])).await;
	let snapshot = provider.publish_snapshot(ZONE).await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	assert_eq!(snapshot.revision, None);
	assert!(
		snapshot
			.records
			.iter()
			.any(|o| o.record == a("203.0.113.10") && o.identity.is_none())
	);
	assert_eq!(snapshot.records.len(), 5);
}

#[tokio::test]
async fn a_value_added_after_the_listing_stops_the_write() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	zone.lock().unwrap().sets = zone_with(&["203.0.113.10", "203.0.113.99"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.10", "203.0.113.99"]);
	assert!(zone.lock().unwrap().batches.is_empty());
}

#[tokio::test]
async fn a_value_replaced_after_the_listing_stops_the_write() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	zone.lock().unwrap().sets = zone_with(&["203.0.113.50"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.50"]);
	assert!(zone.lock().unwrap().batches.is_empty());
}

#[tokio::test]
async fn a_set_that_appeared_where_the_plan_saw_none_stops_the_write() {
	let (provider, zone) = start(zone_with(&[])).await;
	let change = change(&provider, Precondition::Absent, |_| vec![a("203.0.113.11")]).await;
	zone.lock().unwrap().sets = zone_with(&["203.0.113.99"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.99"]);
}

/// The change another account makes after the provider read the set and
/// before its batch arrives, which only the API can see: the `DELETE` no
/// longer matches the live set and Route 53 refuses the whole batch.
#[tokio::test]
async fn a_set_changed_between_the_read_and_the_batch_is_refused_by_the_api() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	zone.lock().unwrap().race = Some(zone_with(&["203.0.113.10", "203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.10", "203.0.113.99"]);
}

#[tokio::test]
async fn a_set_created_between_the_read_and_the_batch_is_refused_by_the_api() {
	let (provider, zone) = start(zone_with(&[])).await;
	let change = change(&provider, Precondition::Absent, |_| vec![a("203.0.113.11")]).await;
	zone.lock().unwrap().race = Some(zone_with(&["203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.99"]);
}

#[tokio::test]
async fn a_set_deleted_between_the_read_and_the_batch_is_refused_by_the_api() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	zone.lock().unwrap().race = Some(zone_with(&[]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert!(live_a(&zone).is_empty());
}

#[tokio::test]
async fn a_removal_after_a_race_leaves_the_value_another_account_added() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| Vec::new()).await;
	zone.lock().unwrap().race = Some(zone_with(&["203.0.113.10", "203.0.113.99"]));
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(live_a(&zone), ["203.0.113.10", "203.0.113.99"]);
}

#[tokio::test]
async fn a_replacement_deletes_the_set_as_read_and_creates_the_new_one_in_one_batch() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| {
		vec![a("203.0.113.11")]
	})
	.await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	let z = zone.lock().unwrap();
	assert_eq!(z.batches.len(), 1, "one batch");
	let body = &z.batches[0];
	let delete = body.find("<Action>DELETE</Action>").expect("a DELETE");
	let create = body.find("<Action>CREATE</Action>").expect("a CREATE");
	assert!(delete < create, "{body}");
	assert!(!body.contains("UPSERT"), "{body}");
	assert!(body[delete..create].contains("<Value>203.0.113.10</Value>"));
	assert!(body[create..].contains("<Value>203.0.113.11</Value>"));
	drop(z);
	assert_eq!(live_a(&zone), ["203.0.113.11"]);
	// The set at another name and the TXT at the same one are untouched.
	let z = zone.lock().unwrap();
	assert!(z.sets.iter().any(|s| s.name == "other.example.org."));
	assert!(z.sets.iter().any(|s| s.kind == "TXT"));
}

#[tokio::test]
async fn a_first_record_is_created_without_a_delete() {
	let (provider, zone) = start(zone_with(&[])).await;
	let change = change(&provider, Precondition::Absent, |_| vec![a("203.0.113.11")]).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	let body = zone.lock().unwrap().batches[0].clone();
	assert!(!body.contains("DELETE"), "{body}");
	assert_eq!(live_a(&zone), ["203.0.113.11"]);
}

#[tokio::test]
async fn a_removal_of_the_last_value_deletes_the_set_as_read() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |_| Vec::new()).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	let body = zone.lock().unwrap().batches[0].clone();
	assert!(!body.contains("CREATE"), "{body}");
	assert!(live_a(&zone).is_empty());
}

#[tokio::test]
async fn a_change_that_alters_nothing_posts_nothing() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let change = change(&provider, Precondition::Identity, |held| held.to_vec()).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert!(zone.lock().unwrap().batches.is_empty());
}

#[tokio::test]
async fn a_change_outside_its_name_is_refused_before_anything_is_written() {
	let (provider, zone) = start(zone_with(&["203.0.113.10"])).await;
	let other = DnsRecord::new("other.example.org", RecordKind::A, "203.0.113.11", 300);
	let change = change(&provider, Precondition::Identity, |_| vec![other]).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert!(zone.lock().unwrap().batches.is_empty());
}

/// An alias, or a set with a routing policy, is not the plain set a batch
/// names: it is refused, never replaced.
#[tokio::test]
async fn an_alias_or_a_routed_set_is_left_alone() {
	for extra in [
		"<AliasTarget><HostedZoneId>Z2</HostedZoneId><DNSName>lb.example.net.</DNSName>\
<EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>",
		"<SetIdentifier>blue</SetIdentifier><Weight>10</Weight>",
	] {
		let mut sets = zone_with(&[]);
		let mut routed = set("mail.example.org.", "A", &[]);
		if extra.contains("SetIdentifier") {
			routed.values = vec!["203.0.113.10".into()];
		}
		routed.extra = extra.to_string();
		sets.push(routed);
		let (provider, zone) = start(sets).await;
		let change = Change {
			name: NAME.into(),
			kind: RecordKind::A,
			before: Vec::new(),
			after: vec![a("203.0.113.11")],
			precondition: Precondition::Absent,
			operation_id: "epistle-publish-test".into(),
		};
		let receipt = provider.apply_guarded(ZONE, change).await;
		assert!(
			matches!(&receipt, Receipt::Rejected(reason) if reason.contains("routing policy")),
			"{receipt:?}"
		);
		assert!(zone.lock().unwrap().batches.is_empty());
	}
}

/// A change in a zone that is not the hosted zone is refused: Route 53 would
/// write it in the hosted zone whatever the name of the zone asked for.
#[tokio::test]
async fn a_change_in_another_zone_is_refused() {
	let (provider, zone) = start(zone_with(&[])).await;
	let change = Change {
		name: "mail.example.net".into(),
		kind: RecordKind::A,
		before: Vec::new(),
		after: vec![DnsRecord::new(
			"mail.example.net",
			RecordKind::A,
			"203.0.113.11",
			300,
		)],
		precondition: Precondition::Absent,
		operation_id: "epistle-publish-test".into(),
	};
	let receipt = provider.apply_guarded("example.net", change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert!(zone.lock().unwrap().batches.is_empty());
}

/// A refusal is a failed precondition only when Route 53 says the set is not
/// the one the batch named; anything else is a refusal, and a server error
/// leaves the outcome unknown.
#[test]
fn the_answer_to_a_batch_is_read_by_its_message() {
	use crate::dns::providers::guarded::Stop;
	use reqwest::StatusCode;
	let stale = "<InvalidChangeBatch><Messages><Message>Tried to delete resource record set \
[name='mail.example.org.', type='A'] but the values provided do not match the current values\
</Message></Messages></InvalidChangeBatch>";
	assert!(matches!(
		super::super::guarded::verdict(StatusCode::BAD_REQUEST, stale),
		Stop::Changed
	));
	let invalid = "<InvalidChangeBatch><Messages><Message>Invalid Resource Record: \
FATAL problem: ARRDATAIllegalIPv4Address</Message></Messages></InvalidChangeBatch>";
	assert!(matches!(
		super::super::guarded::verdict(StatusCode::BAD_REQUEST, invalid),
		Stop::Refused(_)
	));
	assert!(matches!(
		super::super::guarded::verdict(StatusCode::INTERNAL_SERVER_ERROR, ""),
		Stop::Unknown
	));
	assert!(matches!(
		super::super::guarded::verdict(StatusCode::FORBIDDEN, ""),
		Stop::Refused(_)
	));
}
