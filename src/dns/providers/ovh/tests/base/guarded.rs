//! The guarded write of the OVH provider, against the mock of its API.

use super::*;
use crate::dns::providers::tests::guarded_contract::{Rig, guarded_contract};
use crate::dns::publish::provider::Guard;

const ZONE: &str = "example.org";

struct Zone {
	provider: OvhProvider,
	state: Shared,
}

fn stored(id: u64, sub: &str, kind: &str, target: &str) -> StoredRecord {
	StoredRecord {
		id,
		field_type: kind.into(),
		sub_domain: sub.into(),
		target: target.into(),
		ttl: 300,
	}
}

fn zone_records(records: &[(&str, &str)]) -> Vec<StoredRecord> {
	// Besides the records of the case, the zone holds a record at another
	// name and a TXT at the same one. The change must leave both alone.
	let unrelated = [
		stored(900, "other", "A", "198.51.100.1"),
		stored(901, "mail", "TXT", "v=spf1 -all"),
	];
	records
		.iter()
		.map(|(id, value)| stored(id.parse().unwrap(), "mail", "A", value))
		.chain(unrelated)
		.collect()
}

impl Rig for Zone {
	async fn start(records: &[(&str, &str)]) -> Self {
		let (provider, state) = mock_with(zone_records(records)).await;
		Zone { provider, state }
	}

	fn provider(&self) -> &dyn DnsProvider {
		&self.provider
	}

	fn set(&self, records: &[(&str, &str)]) {
		self.state.lock().unwrap().records = zone_records(records);
	}

	fn writes(&self) -> Vec<String> {
		self.state.lock().unwrap().writes.clone()
	}

	fn written_addresses(&self) -> Vec<String> {
		self.state.lock().unwrap().targets.clone()
	}
}

guarded_contract!(Zone);

#[tokio::test]
async fn the_zone_is_refreshed_after_a_change_that_wrote_and_not_after_one_that_did_not() {
	let rig = Zone::start(&[("100", "203.0.113.20"), ("101", "203.0.113.10")]).await;
	let snapshot = rig.provider().publish_snapshot(ZONE).await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	let before: Vec<_> = snapshot
		.records
		.into_iter()
		.filter(|o| o.record.name == "mail.example.org" && o.record.kind == RecordKind::A)
		.collect();
	let kept: Vec<DnsRecord> = before.iter().map(|o| o.record.clone()).collect();
	let change = |after: Vec<DnsRecord>| crate::dns::publish::provider::Change {
		name: "mail.example.org".into(),
		kind: RecordKind::A,
		before: before.clone(),
		after,
		precondition: crate::dns::publish::provider::Precondition::Identity,
		operation_id: "epistle-publish-test".into(),
	};
	rig.provider()
		.apply_guarded(ZONE, change(kept.clone()))
		.await;
	assert!(!rig.state.lock().unwrap().refresh_called);
	let mut after = kept;
	after.push(DnsRecord::new(
		"mail.example.org",
		RecordKind::A,
		"203.0.113.11",
		300,
	));
	rig.provider().apply_guarded(ZONE, change(after)).await;
	assert!(rig.state.lock().unwrap().refresh_called);
}
