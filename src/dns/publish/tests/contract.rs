//! A provider that does not implement the guarded contract writes nothing.
//! The three new methods default to refusing, and the default of the
//! guarded write never falls back to `upsert`: a write that cannot be
//! conditioned may destroy the records of somebody else.

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, ManualProvider, ProviderError, RecordKind};
use std::sync::Mutex;

/// A provider that only knows the old contract, and counts what it was
/// asked to write.
#[derive(Default)]
struct OldProvider {
	writes: Mutex<Vec<DnsRecord>>,
}

impl OldProvider {
	/// The records it was asked to write.
	fn writes(&self) -> Vec<DnsRecord> {
		self.writes.lock().unwrap().clone()
	}
}

impl DnsProvider for OldProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async move {
			self.writes.lock().unwrap().push(record);
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async move {
			self.writes.lock().unwrap().push(record);
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> crate::dns::provider::ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A change that would create a DMARC record.
fn change() -> Change {
	Change {
		name: "_dmarc.example.org".to_string(),
		kind: RecordKind::Txt,
		before: Vec::new(),
		after: vec![DnsRecord::new(
			"_dmarc.example.org",
			RecordKind::Txt,
			"v=DMARC1; p=quarantine",
			3600,
		)],
		precondition: Precondition::Absent,
		operation_id: "operation-1".to_string(),
	}
}

/// An adapter that does not know the guarded contract refuses the change,
/// and writes nothing at all: the old write is never used as a way out.
#[tokio::test]
async fn an_old_adapter_does_not_write() {
	let provider = OldProvider::default();
	let receipt = provider.apply_guarded("example.org", change()).await;
	assert!(
		provider.writes().is_empty(),
		"an adapter that does not implement the guarded contract must not write"
	);
	assert_eq!(receipt, Receipt::Unsupported);
}

/// The snapshot the default takes is the listing and nothing more: no
/// revision, no identity, and a provider that says nothing about a
/// precondition is unchecked.
#[tokio::test]
async fn the_default_snapshot_is_unchecked() {
	let provider = OldProvider::default();
	let snapshot = provider
		.publish_snapshot("example.org")
		.await
		.expect("snapshot");
	assert_eq!(snapshot.zone, "example.org");
	assert_eq!(snapshot.guard, Guard::Unchecked);
	assert!(snapshot.revision.is_none());
	assert!(snapshot.records.is_empty());
}

/// Manual mode has no API behind it, so it hands out no snapshot: its
/// listing is empty because there is nothing to read, not because the zone
/// is empty.
#[tokio::test]
async fn manual_mode_hands_out_no_snapshot() {
	let provider = ManualProvider;
	assert_eq!(
		provider.publish_snapshot("example.org").await,
		Err(ProviderError::Unsupported)
	);
}

/// A provider that keeps no record of its operations cannot resolve a lost
/// answer, and the default says so instead of dressing it up as a success.
#[tokio::test]
async fn the_default_lookup_says_the_capability_is_absent() {
	let provider = OldProvider::default();
	assert_eq!(
		provider
			.lookup_operation("operation-1")
			.await
			.expect("lookup"),
		OperationOutcome::Unsupported
	);
}
