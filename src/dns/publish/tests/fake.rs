//! The protected double keeps what it was given, refuses a change whose
//! precondition does not hold, and remembers the operation it applied so
//! an answer that was lost can be resolved afterwards.

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

/// A TXT record at a name.
fn record(name: &str, value: &str) -> DnsRecord {
	DnsRecord::new(name, RecordKind::Txt, value, 3600)
}

/// The change that replaces the value of the record at a name.
fn change(before: Vec<ObservedRecord>, value: &str) -> Change {
	Change {
		name: "_dmarc.example.org".to_string(),
		kind: RecordKind::Txt,
		before,
		after: vec![record("_dmarc.example.org", value)],
		precondition: Precondition::Identity,
		operation_id: "operation-1".to_string(),
	}
}

/// The double keeps the records it was given, with an identity of their
/// own and a revision it can name.
#[tokio::test]
async fn the_fake_snapshots_what_it_holds() {
	let provider =
		FakeGuardedProvider::holding(vec![record("_dmarc.example.org", "v=DMARC1; p=none")]);
	let snapshot = provider
		.publish_snapshot("example.org")
		.await
		.expect("snapshot");
	assert_eq!(snapshot.zone, "example.org");
	assert_eq!(snapshot.guard, Guard::Checked);
	assert_eq!(snapshot.records.len(), 1);
	assert_eq!(snapshot.records[0].record.value, "v=DMARC1; p=none");
	assert!(snapshot.records[0].identity.is_some());
	assert!(snapshot.revision.is_some());
}

/// A change whose precondition still holds is applied, and the operation
/// is remembered under its own name.
#[tokio::test]
async fn the_fake_applies_a_change_whose_precondition_holds() {
	let provider =
		FakeGuardedProvider::holding(vec![record("_dmarc.example.org", "v=DMARC1; p=none")]);
	let snapshot = provider
		.publish_snapshot("example.org")
		.await
		.expect("snapshot");
	let receipt = provider
		.apply_guarded(
			"example.org",
			change(snapshot.records.clone(), "v=DMARC1; p=quarantine"),
		)
		.await;
	assert!(
		matches!(receipt, Receipt::Applied { .. }),
		"a change whose precondition holds must be applied"
	);
	assert_eq!(provider.records().len(), 1);
	assert_eq!(provider.records()[0].value, "v=DMARC1; p=quarantine");
	assert_eq!(
		provider
			.lookup_operation("operation-1")
			.await
			.expect("lookup"),
		OperationOutcome::Applied
	);
}

/// A change planned against a listing that is no longer true is refused,
/// and nothing is written: the records of somebody else stay as they are.
#[tokio::test]
async fn the_fake_refuses_a_change_whose_precondition_does_not_hold() {
	let provider =
		FakeGuardedProvider::holding(vec![record("_dmarc.example.org", "v=DMARC1; p=none")]);
	let snapshot = provider
		.publish_snapshot("example.org")
		.await
		.expect("snapshot");
	let planned = change(snapshot.records.clone(), "v=DMARC1; p=quarantine");
	// Somebody else writes to the zone after the snapshot was taken.
	provider
		.upsert(
			"example.org",
			record("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("write");

	let receipt = provider.apply_guarded("example.org", planned).await;
	assert_eq!(receipt, Receipt::PreconditionFailed);
	assert_eq!(provider.records().len(), 1);
	assert_eq!(provider.records()[0].value, "v=DMARC1; p=reject");
}

/// A change that creates a record is refused while something else lives at
/// that name, and applied when the name is free.
#[tokio::test]
async fn the_fake_creates_a_record_only_where_the_name_is_free() {
	let provider = FakeGuardedProvider::holding(Vec::new());
	let create = Change {
		name: "_dmarc.example.org".to_string(),
		kind: RecordKind::Txt,
		before: Vec::new(),
		after: vec![record("_dmarc.example.org", "v=DMARC1; p=quarantine")],
		precondition: Precondition::Absent,
		operation_id: "operation-1".to_string(),
	};
	assert!(matches!(
		provider.apply_guarded("example.org", create.clone()).await,
		Receipt::Applied { .. }
	));
	assert_eq!(provider.records().len(), 1);

	// The name is taken now, so a second create is refused.
	assert_eq!(
		provider.apply_guarded("example.org", create).await,
		Receipt::PreconditionFailed
	);
	assert_eq!(provider.records().len(), 1);
}

/// The double keeps the siblings of a TXT: a write of one purpose leaves
/// the other records at the name as they are.
#[tokio::test]
async fn the_fake_keeps_the_siblings_of_a_txt() {
	let provider = FakeGuardedProvider::holding(vec![
		record("_dmarc.example.org", "v=DMARC1; p=none"),
		record("_dmarc.example.org", "token-acme"),
	]);
	provider
		.upsert(
			"example.org",
			record("_dmarc.example.org", "v=DMARC1; p=quarantine"),
		)
		.await
		.expect("write");
	let values: Vec<String> = provider
		.records()
		.into_iter()
		.map(|held| held.value)
		.collect();
	assert_eq!(values.len(), 2, "the sibling must survive the write");
	assert!(values.contains(&"v=DMARC1; p=quarantine".to_string()));
	assert!(values.contains(&"token-acme".to_string()));
}

/// An operation the double never saw is unknown to it, and that is not a
/// success either.
#[tokio::test]
async fn the_fake_does_not_know_an_operation_it_never_ran() {
	let provider = FakeGuardedProvider::holding(Vec::new());
	assert_eq!(
		provider
			.lookup_operation("operation-9")
			.await
			.expect("lookup"),
		OperationOutcome::Unknown
	);
}
