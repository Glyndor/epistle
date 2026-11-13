//! The guarded write of the DNSimple provider, against the mock of its API.

use super::*;
use crate::dns::providers::tests::guarded_contract::{Rig, guarded_contract};

struct Zone {
	provider: DnsimpleProvider,
	state: Shared,
}

fn zone_records(records: &[(&str, &str)]) -> Vec<serde_json::Value> {
	// Besides the records of the case, the zone holds a record at another
	// name and a TXT at the same one. The change must leave both alone.
	let unrelated = [
		record(900, "other", "A", "198.51.100.1", 300),
		record(901, "mail", "TXT", "v=spf1 -all", 300),
	];
	records
		.iter()
		.map(|(id, value)| record(id.parse().unwrap(), "mail", "A", value, 300))
		.chain(unrelated)
		.collect()
}

impl Rig for Zone {
	async fn start(records: &[(&str, &str)]) -> Self {
		let (provider, state) = mock(zone_records(records)).await;
		Zone { provider, state }
	}

	fn provider(&self) -> &dyn DnsProvider {
		&self.provider
	}

	fn set(&self, records: &[(&str, &str)]) {
		self.state.lock().unwrap().records = zone_records(records);
	}

	fn writes(&self) -> Vec<String> {
		self.state
			.lock()
			.unwrap()
			.calls
			.iter()
			.filter(|call| !call.starts_with("GET"))
			.map(|call| match call.rsplit_once("/records/") {
				None => "create".to_string(),
				Some((verb, id)) if verb.starts_with("PATCH") => format!("update {id}"),
				Some((_, id)) => format!("delete {id}"),
			})
			.collect()
	}

	fn written_addresses(&self) -> Vec<String> {
		self.state
			.lock()
			.unwrap()
			.bodies
			.iter()
			.map(|body| {
				let body: serde_json::Value = serde_json::from_str(body).unwrap();
				body["content"].as_str().unwrap().to_string()
			})
			.collect()
	}
}

guarded_contract!(Zone);

#[tokio::test]
async fn a_tlsa_the_provider_cannot_take_is_refused_before_any_write() {
	let rig = Zone::start(&[("101", "203.0.113.10")]).await;
	let tlsa = DnsRecord::new("mail.example.org", RecordKind::Tlsa, "3 1 1 00", 300);
	let change = crate::dns::publish::provider::Change {
		name: tlsa.name.clone(),
		kind: RecordKind::Tlsa,
		before: Vec::new(),
		after: vec![tlsa],
		precondition: crate::dns::publish::provider::Precondition::Absent,
		operation_id: "epistle-publish-test".into(),
	};
	let receipt = rig.provider().apply_guarded(ZONE, change).await;
	assert!(
		matches!(receipt, crate::dns::publish::provider::Receipt::Rejected(_)),
		"{receipt:?}"
	);
	assert_eq!(rig.writes(), Vec::<String>::new());
}
