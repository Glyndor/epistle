//! The guarded write of the Bunny provider, against the mock of its API.

use super::*;
use crate::dns::providers::tests::guarded_contract::{Rig, guarded_contract};

struct Zone {
	provider: BunnyProvider,
	state: Shared,
}

fn detail(records: &[(&str, &str)]) -> serde_json::Value {
	// Besides the records of the case, the zone holds a record at another
	// name and a TXT at the same one. The change must leave both alone.
	let unrelated = [
		serde_json::json!({"Id": 900, "Type": 0, "Name": "other", "Value": "198.51.100.1", "Ttl": 300}),
		serde_json::json!({"Id": 901, "Type": 3, "Name": "mail", "Value": "v=spf1 -all", "Ttl": 300}),
	];
	let records: Vec<serde_json::Value> = records
		.iter()
		.map(|(id, value)| {
			serde_json::json!({
				"Id": id.parse::<i64>().unwrap(), "Type": 0, "Name": "mail",
				"Value": value, "Ttl": 300
			})
		})
		.chain(unrelated)
		.collect();
	serde_json::json!({ "Id": 42, "Records": records })
}

impl Rig for Zone {
	async fn start(records: &[(&str, &str)]) -> Self {
		let (provider, state) = mock().await;
		state.lock().unwrap().zone_detail = detail(records);
		Zone { provider, state }
	}

	fn provider(&self) -> &dyn DnsProvider {
		&self.provider
	}

	fn set(&self, records: &[(&str, &str)]) {
		self.state.lock().unwrap().zone_detail = detail(records);
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
				Some((verb, id)) if verb.starts_with("POST") => format!("update {id}"),
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
				body["Value"].as_str().unwrap().to_string()
			})
			.collect()
	}
}

guarded_contract!(Zone);
