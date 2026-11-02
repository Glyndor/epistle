//! The refresh replaces only the TLSA values this instance published. A
//! record of somebody else at the same name survives it, and a provider
//! that cannot replace one value only is not given a write that would take
//! the others with it.

use super::support::{HOST, Zone, certificate};
use super::*;
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::publish::provider::FakeGuardedProvider;

const NAME: &str = "_25._tcp.mail.example.org";

fn tlsa(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::Tlsa, value, 3600)
}

fn target<'a>(provider: &'a dyn DnsProvider, dir: &'a Path) -> Target<'a> {
	Target {
		provider: Some(provider),
		hostname: HOST,
		data_dir: dir,
	}
}

fn values(records: Vec<DnsRecord>) -> Vec<String> {
	let mut values: Vec<String> = records
		.into_iter()
		.filter(|record| record.kind == RecordKind::Tlsa)
		.map(|record| record.value)
		.collect();
	values.sort();
	values
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
	values.sort();
	values
}

const FOREIGN: &str = "3 0 1 00000000000000000000000000000000000000000000000000000000000000ff";

#[tokio::test]
async fn a_provider_that_replaces_whole_sets_never_removes_a_foreign_record() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::holding(vec![tlsa(FOREIGN)]);
	let (pem, value) = certificate();

	let outcome = refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	match outcome {
		Outcome::Pending { reason, .. } => {
			assert!(reason.contains("did not publish"), "{reason}");
			assert!(reason.contains(FOREIGN), "the record is named: {reason}");
		}
		other => panic!("a foreign record blocks the write, got {other:?}"),
	}
	assert_eq!(zone.writes(), 0, "nothing was written");
	assert_eq!(zone.values(), vec![FOREIGN.to_string()], "the record stays");
	assert!(!zone.values().contains(&value));
}

#[tokio::test]
async fn the_value_of_the_certificate_just_replaced_is_ours_to_replace() {
	let dir = tempfile::tempdir().expect("dir");
	let (old_pem, old_value) = certificate();
	let (new_pem, new_value) = certificate();
	let zone = Zone::holding(vec![tlsa(&old_value)]);

	let outcome = refresh(&target(&zone, dir.path()), &new_pem, Some(&old_pem), 1_000).await;

	assert_eq!(
		outcome,
		Outcome::Published {
			value: new_value.clone()
		}
	);
	assert_eq!(zone.values(), vec![new_value]);
}

#[tokio::test]
async fn a_value_the_state_remembers_is_ours_to_replace() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	let (first_pem, first_value) = certificate();
	let (second_pem, second_value) = certificate();
	refresh(&target(&zone, dir.path()), &first_pem, None, 1_000).await;
	assert_eq!(zone.values(), vec![first_value]);

	// A restart forgot the previous chain; the state still knows the value.
	let outcome = refresh(&target(&zone, dir.path()), &second_pem, None, 2_000).await;

	assert_eq!(
		outcome,
		Outcome::Published {
			value: second_value.clone()
		}
	);
	assert_eq!(zone.values(), vec![second_value]);
}

#[tokio::test]
async fn a_value_nobody_here_published_is_foreign_even_with_the_state_lost() {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, _) = certificate();
	let (_, other_value) = certificate();
	let zone = Zone::holding(vec![tlsa(&other_value)]);

	let outcome = refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	assert!(matches!(outcome, Outcome::Pending { .. }));
	assert_eq!(zone.values(), vec![other_value]);
}

#[tokio::test]
async fn an_already_published_value_is_not_written_again() {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, value) = certificate();
	let zone = Zone::holding(vec![tlsa(&value), tlsa(FOREIGN)]);

	let outcome = refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	assert_eq!(
		outcome,
		Outcome::Published {
			value: value.clone()
		}
	);
	assert_eq!(zone.writes(), 0);
	assert_eq!(
		sorted(zone.values()),
		sorted(vec![value, FOREIGN.to_string()])
	);
}

#[tokio::test]
async fn a_guarded_provider_keeps_the_foreign_record_and_the_old_value_beside_the_new() {
	let dir = tempfile::tempdir().expect("dir");
	let (old_pem, old_value) = certificate();
	let (new_pem, new_value) = certificate();
	let provider = FakeGuardedProvider::holding(vec![tlsa(FOREIGN), tlsa(&old_value)]);

	let outcome = refresh(
		&target(&provider, dir.path()),
		&new_pem,
		Some(&old_pem),
		1_000,
	)
	.await;

	assert_eq!(
		outcome,
		Outcome::Published {
			value: new_value.clone()
		}
	);
	assert_eq!(
		values(provider.records()),
		sorted(vec![FOREIGN.to_string(), new_value, old_value]),
		"the new value is published before the old one is withdrawn"
	);
}

#[tokio::test]
async fn the_next_rotation_withdraws_the_value_before_the_overlap() {
	let dir = tempfile::tempdir().expect("dir");
	let (first_pem, first_value) = certificate();
	let (second_pem, second_value) = certificate();
	let (third_pem, third_value) = certificate();
	let provider = FakeGuardedProvider::holding(vec![tlsa(FOREIGN), tlsa(&first_value)]);
	refresh(
		&target(&provider, dir.path()),
		&second_pem,
		Some(&first_pem),
		1_000,
	)
	.await;

	refresh(
		&target(&provider, dir.path()),
		&third_pem,
		Some(&second_pem),
		2_000,
	)
	.await;

	assert_eq!(
		values(provider.records()),
		sorted(vec![FOREIGN.to_string(), third_value, second_value]),
		"the first value is gone, the foreign one never was"
	);
}

/// A provider that cannot list its zone, the shape of a write-only API.
struct WriteOnly {
	upserts: std::sync::Mutex<Vec<DnsRecord>>,
}

impl DnsProvider for WriteOnly {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.upserts.lock().expect("upserts").push(record);
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> crate::dns::provider::ListOp<'_> {
		Box::pin(async { Err(crate::dns::provider::ProviderError::Unsupported) })
	}
}

#[tokio::test]
async fn a_provider_that_cannot_list_keeps_the_whole_set_write() {
	let dir = tempfile::tempdir().expect("dir");
	let provider = WriteOnly {
		upserts: std::sync::Mutex::new(Vec::new()),
	};
	let (pem, value) = certificate();

	let outcome = refresh(&target(&provider, dir.path()), &pem, None, 1_000).await;

	assert_eq!(outcome, Outcome::Published { value });
	assert_eq!(provider.upserts.lock().expect("upserts").len(), 1);
}
