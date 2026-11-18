//! The guarded writer of one record set: it writes the set the plan makes of
//! the one it read, leaves every other record alone, writes nothing when the
//! zone changed after the read, and gives a provider that checks no
//! precondition the ordinary write.

use std::sync::{Arc, Mutex};

use super::*;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
use crate::dns::publish::write::{Unguarded, WriteError, replace_set};

const NAME: &str = "_acme-challenge.example.org";

fn txt(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::Txt, value, 60)
}

/// The plan of a dns-01 publish: the set as it was, with `value` added.
fn adding(value: &'static str) -> impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord> {
	move |held| held.iter().cloned().chain([txt(value)]).collect()
}

fn values(provider: &FakeGuardedProvider) -> Vec<String> {
	let mut values: Vec<String> = provider.records().into_iter().map(|r| r.value).collect();
	values.sort();
	values
}

/// The double, with a record another account adds right after the snapshot,
/// before the change arrives.
struct Racing {
	inner: FakeGuardedProvider,
	race: Mutex<Option<DnsRecord>>,
}

type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for Racing {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.inner.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.inner.delete(zone, record)
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		self.inner.list(zone)
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(async move {
			let snapshot = self.inner.publish_snapshot(zone).await;
			let race = self.race.lock().unwrap().take();
			if let Some(record) = race {
				self.inner.upsert(zone, record).await.unwrap();
			}
			snapshot
		})
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		self.inner.apply_guarded(zone, change)
	}
}

/// Records every ordinary write; it lists nothing and checks no
/// precondition.
#[derive(Default)]
struct Unchecked(Mutex<Vec<String>>);

impl DnsProvider for Unchecked {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.0
			.lock()
			.unwrap()
			.push(format!("upsert {}", record.value));
		Box::pin(async { Ok(()) })
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.0
			.lock()
			.unwrap()
			.push(format!("delete {}", record.value));
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn the_planned_set_is_written_and_the_record_of_somebody_else_stays() {
	let provider = FakeGuardedProvider::holding(vec![txt("token-sibling")]);
	replace_set(
		&provider,
		"example.org",
		NAME,
		&RecordKind::Txt,
		adding("token-ours"),
		Unguarded::Upsert(txt("token-ours")),
		"operation-1".into(),
	)
	.await
	.expect("written");
	assert_eq!(values(&provider), ["token-ours", "token-sibling"]);
}

#[tokio::test]
async fn a_record_added_after_the_read_stops_the_write() {
	let provider = Racing {
		inner: FakeGuardedProvider::holding(vec![txt("token-sibling")]),
		race: Mutex::new(Some(txt("token-theirs"))),
	};
	let outcome = replace_set(
		&provider,
		"example.org",
		NAME,
		&RecordKind::Txt,
		|_| vec![txt("token-ours")],
		Unguarded::Upsert(txt("token-ours")),
		"operation-1".into(),
	)
	.await;
	assert_eq!(outcome, Err(WriteError::Changed));
	assert_eq!(values(&provider.inner), ["token-sibling", "token-theirs"]);
}

#[tokio::test]
async fn a_plan_that_changes_nothing_writes_nothing() {
	let provider = FakeGuardedProvider::holding(vec![txt("token-ours")]);
	let before = provider.publish_snapshot("example.org").await.unwrap();
	replace_set(
		&provider,
		"example.org",
		NAME,
		&RecordKind::Txt,
		|held| held.to_vec(),
		Unguarded::Upsert(txt("token-ours")),
		"operation-1".into(),
	)
	.await
	.expect("nothing to write");
	let after = provider.publish_snapshot("example.org").await.unwrap();
	assert_eq!(before.revision, after.revision, "no write went out");
}

#[tokio::test]
async fn a_provider_without_a_precondition_gets_the_ordinary_write() {
	let provider = Arc::new(Unchecked::default());
	for unguarded in [
		Unguarded::Upsert(txt("token-ours")),
		Unguarded::Remove(txt("token-ours")),
		Unguarded::Delete(txt("")),
	] {
		replace_set(
			provider.as_ref(),
			"example.org",
			NAME,
			&RecordKind::Txt,
			|_| Vec::new(),
			unguarded,
			"operation-1".into(),
		)
		.await
		.expect("the ordinary write");
	}
	// The exact removal is not supported, so the removal falls back to the
	// ordinary delete of the value.
	assert_eq!(
		*provider.0.lock().unwrap(),
		["upsert token-ours", "delete token-ours", "delete "]
	);
}
