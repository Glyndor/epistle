//! The `api_keys` check: keys do not live indefinitely, and SCIM keys name
//! the domains they may provision.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::api::api_keys::ApiKeyStore;

/// Read the same key file as `epistle api-key list`, without a server.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(_) => {
			return AreaReport::single(Level::Warn, "cannot load API keys without configuration");
		}
	};
	match ApiKeyStore::open(&config.data_dir) {
		Ok(store) => evaluate(&store, &config.data_dir),
		Err(_) => AreaReport::single(Level::Warn, "cannot read or parse the API key store"),
	}
}

/// Report each missing expiry, each SCIM key without a domain, and each key
/// whose `--ip-cidr` the container network cannot decide.
fn evaluate(store: &ApiKeyStore, data_dir: &std::path::Path) -> AreaReport {
	let clause = super::super::client_address::hidden_clause(data_dir);
	let mut items = Vec::new();
	for key in store.keys() {
		let scopes = if key.scopes.is_empty() {
			"all (legacy)".to_string()
		} else {
			key.scopes.join(", ")
		};
		let name = format!("{} ({scopes})", key.label);
		if key.expires_at.is_none() {
			items.push(Item::new(&name, Level::Warn, "has no expiry"));
		}
		if key.scopes.iter().any(|scope| scope == "scim") && key.domains.is_empty() {
			items.push(Item::new(
				&name,
				Level::Warn,
				"scim key has no associated domain",
			));
		}
		if let (Some(cidr), Some(clause)) = (&key.ip_cidr, &clause) {
			items.push(Item::new(
				&name,
				Level::Warn,
				format!(
					"pinned to {cidr}, which is matched against the address the server sees, \
					 and {clause}: it does not see the client address"
				),
			));
		}
	}
	let summary = if items.is_empty() {
		format!("{} keys checked", store.keys().len())
	} else {
		format!("{} API key warnings", items.len())
	};
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
#[path = "api_keys_area_tests.rs"]
mod tests;
