//! The guarded write of the DigitalOcean provider, against the mock of its
//! v2 API.

use super::base::{Shared, mock};
use super::*;
use crate::dns::providers::tests::guarded_contract::{Rig, guarded_contract};

struct Zone {
	provider: DigitaloceanProvider,
	state: Shared,
}

/// What the zone holds besides the records of the case: a record at another
/// name and a TXT at the same one. The change must leave both alone.
fn unrelated() -> Vec<serde_json::Value> {
	vec![
		serde_json::json!({"id": 900, "type": "A", "name": "other", "data": "198.51.100.1", "ttl": 300}),
		serde_json::json!({"id": 901, "type": "TXT", "name": "mail", "data": "v=spf1 -all", "ttl": 300}),
	]
}

fn zone_of(records: &[(&str, &str)]) -> Vec<serde_json::Value> {
	records
		.iter()
		.map(|(i, v)| stored(i, v))
		.chain(unrelated())
		.collect()
}

fn stored(id: &str, value: &str) -> serde_json::Value {
	serde_json::json!({
		"id": id.parse::<u64>().unwrap(),
		"type": "A", "name": "mail", "data": value, "ttl": 300
	})
}

impl Rig for Zone {
	async fn start(records: &[(&str, &str)]) -> Self {
		let (provider, state) = mock(zone_of(records), false).await;
		Zone { provider, state }
	}

	fn provider(&self) -> &dyn DnsProvider {
		&self.provider
	}

	fn set(&self, records: &[(&str, &str)]) {
		self.state.lock().unwrap().records = zone_of(records);
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
				Some((verb, id)) if verb.starts_with("PUT") => format!("update {id}"),
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
				body["data"].as_str().unwrap().to_string()
			})
			.collect()
	}
}

guarded_contract!(Zone);
