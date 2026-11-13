//! The guarded write of the Porkbun provider, against the mock of its API.

use super::*;
use crate::dns::providers::tests::guarded_contract::{Rig, guarded_contract};

struct Zone {
	provider: PorkbunProvider,
	state: Shared,
}

/// The zone holds, besides the records of the case, a record at another name
/// and a TXT at the same one. The change must leave both alone.
fn listed(records: &[(&str, &str)]) -> serde_json::Value {
	let unrelated = [
		("900", "other.example.org", "A", "198.51.100.1"),
		("901", "mail.example.org", "TXT", "v=spf1 -all"),
	];
	records
		.iter()
		.map(|(id, value)| (*id, "mail.example.org", "A", *value))
		.chain(unrelated)
		.map(|(id, name, kind, content)| {
			serde_json::json!({
				"id": id, "name": name, "type": kind,
				"content": content, "ttl": "300", "prio": "0", "notes": ""
			})
		})
		.collect()
}

impl Rig for Zone {
	async fn start(records: &[(&str, &str)]) -> Self {
		let (provider, state) = mock(listed(records)).await;
		Zone { provider, state }
	}

	fn provider(&self) -> &dyn DnsProvider {
		&self.provider
	}

	fn set(&self, records: &[(&str, &str)]) {
		self.state.lock().unwrap().records = listed(records);
	}

	fn writes(&self) -> Vec<String> {
		self.state
			.lock()
			.unwrap()
			.calls
			.iter()
			.filter(|call| !call.path.starts_with("/dns/retrieve/"))
			.map(|call| {
				let mut parts = call.path.trim_start_matches("/dns/").split('/');
				match (parts.next(), parts.nth(1)) {
					(Some("create"), _) => "create".to_string(),
					(Some("edit"), Some(id)) => format!("update {id}"),
					(Some("delete"), Some(id)) => format!("delete {id}"),
					_ => call.path.clone(),
				}
			})
			.collect()
	}

	fn written_addresses(&self) -> Vec<String> {
		self.state
			.lock()
			.unwrap()
			.calls
			.iter()
			.filter(|call| {
				call.path.starts_with("/dns/create/") || call.path.starts_with("/dns/edit/")
			})
			.map(|call| call.body["content"].as_str().unwrap().to_string())
			.collect()
	}
}

guarded_contract!(Zone);
