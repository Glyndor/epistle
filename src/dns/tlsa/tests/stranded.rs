//! A value this instance published is withdrawn at a later rotation, even
//! when the refreshes in between did not reach the zone.

use std::sync::atomic::{AtomicU32, Ordering};

use super::support::{HOST, certificate};
use super::*;
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::publish::provider::{Change, FakeGuardedProvider, Receipt, ReceiptOp, SnapshotOp};

const NAME: &str = "_25._tcp.mail.example.org";

/// The guarded provider of the contract, which refuses the first `refusals`
/// changes it is given.
struct Refusing {
	zone: FakeGuardedProvider,
	refusals: AtomicU32,
}

impl DnsProvider for Refusing {
	fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.upsert(zone, record)
	}

	fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.delete(zone, record)
	}

	fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
		self.zone.list(zone)
	}

	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		self.zone.publish_snapshot(zone)
	}

	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		let mut refused = false;
		let mut left = self.refusals.load(Ordering::SeqCst);
		while left > 0 {
			match self
				.refusals
				.compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst)
			{
				Ok(_) => {
					refused = true;
					break;
				}
				Err(now) => left = now,
			}
		}
		if refused {
			return Box::pin(async { Receipt::Rejected("the provider is down".into()) });
		}
		self.zone.apply_guarded(zone, change)
	}
}

fn target<'a>(provider: &'a dyn DnsProvider, dir: &'a Path) -> Target<'a> {
	Target {
		provider: Some(provider),
		hostname: HOST,
		data_dir: dir,
	}
}

fn zone_values(provider: &Refusing) -> Vec<String> {
	let mut values: Vec<String> = provider
		.zone
		.records()
		.into_iter()
		.filter(|record| record.kind == RecordKind::Tlsa)
		.map(|record| record.value)
		.collect();
	values.sort();
	values
}

#[tokio::test]
async fn a_value_left_in_the_zone_by_refreshes_that_failed_is_withdrawn_later() {
	let dir = tempfile::tempdir().expect("dir");
	let (first_pem, first) = certificate();
	let (second_pem, second) = certificate();
	let (third_pem, _) = certificate();
	let (fourth_pem, fourth) = certificate();
	let provider = Refusing {
		zone: FakeGuardedProvider::holding(vec![DnsRecord::new(
			NAME,
			RecordKind::Tlsa,
			&first,
			3600,
		)]),
		refusals: AtomicU32::new(0),
	};
	// The second certificate is published beside the first.
	refresh(
		&target(&provider, dir.path()),
		&second_pem,
		Some(&first_pem),
		1_000,
	)
	.await;
	// The next two are refused: the zone still holds the first two.
	provider.refusals.store(2, Ordering::SeqCst);
	refresh(
		&target(&provider, dir.path()),
		&third_pem,
		Some(&second_pem),
		2_000,
	)
	.await;
	refresh(
		&target(&provider, dir.path()),
		&fourth_pem,
		Some(&third_pem),
		3_000,
	)
	.await;

	// The provider is back and the owed publication goes out.
	let outcome = retry_due(&target(&provider, dir.path()), &fourth_pem, 10_000).await;

	assert_eq!(
		outcome,
		Some(Outcome::Published {
			value: fourth.clone()
		})
	);
	let mut expected = vec![fourth, second];
	expected.sort();
	assert_eq!(
		zone_values(&provider),
		expected,
		"the new value and the one before it; the first is withdrawn, not left for good"
	);
}
