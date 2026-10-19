//! Interpret only documented zone resource policies; unfamiliar shapes stay unknown.

use serde::Deserialize;
use serde_json::Value;

use super::Zone;
use crate::dns::providers::check::Finding;

#[derive(Deserialize)]
pub(super) struct Details {
	pub policies: Option<Vec<Policy>>,
}

#[derive(Deserialize)]
pub(super) struct Policy {
	effect: String,
	permission_groups: Vec<Group>,
	resources: Value,
}

#[derive(Deserialize)]
struct Group {
	name: Option<String>,
}

// None means the resource shape cannot be interpreted without guessing.
fn resources(value: &Value) -> Option<Vec<String>> {
	let object = value.as_object()?;
	let mut zones = Vec::new();
	for (key, value) in object {
		if let Some(id) = key.strip_prefix("com.cloudflare.api.account.zone.") {
			if value != "*" || !(id == "*" || super::valid_id(id)) {
				return None;
			}
			zones.push(id.to_string());
		} else if let Some(id) = key.strip_prefix("com.cloudflare.api.account.") {
			if id != "*" {
				return None;
			}
			if value == "*" {
				zones.push("*".into());
			} else {
				zones.extend(resources(value)?);
			}
		} else if key.starts_with("com.cloudflare.api.user") && value == "*" {
			// User permissions, such as API Tokens Read, do not grant DNS access.
		} else {
			return None;
		}
	}
	Some(zones)
}

pub(super) fn findings(
	policies: &[Policy],
	visible: &[Zone],
	needed: &[&Zone],
) -> (Finding, Finding) {
	let mut writes = Vec::new();
	let mut dns_zones = Vec::new();
	for policy in policies {
		// A deny or unfamiliar policy may override a grant. Do not claim access.
		if policy.effect != "allow" || policy.permission_groups.iter().any(|g| g.name.is_none()) {
			return unknown();
		}
		let Some(zones) = resources(&policy.resources) else {
			return unknown();
		};
		let has_write = policy
			.permission_groups
			.iter()
			.any(|g| g.name.as_deref() == Some("DNS Write"));
		let has_dns = has_write
			|| policy
				.permission_groups
				.iter()
				.any(|g| g.name.as_deref() == Some("DNS Read"));
		if has_write {
			writes.extend(zones.clone());
		}
		if has_dns {
			dns_zones.extend(zones);
		}
	}
	let write = if needed.is_empty() {
		Finding::unknown("no required zone was visible to evaluate DNS Write")
	} else if needed
		.iter()
		.all(|z| writes.iter().any(|id| id == "*" || id == &z.id))
	{
		Finding::verified(
			"token policy grants DNS Write for each visible required zone; no write was attempted",
		)
	} else {
		Finding::failure("token policy does not grant DNS Write for each visible required zone")
	};
	let scope = if dns_zones.iter().any(|id| id == "*") {
		Finding::verified("broader than needed: DNS policy grants account-wide or all-zone access")
	} else if dns_zones
		.iter()
		.any(|id| !needed.iter().any(|z| &z.id == id))
		|| visible.iter().any(|z| !needed.iter().any(|n| n.id == z.id))
	{
		Finding::verified("broader than needed: token has access to extra zones")
	} else {
		Finding::verified("DNS policies are restricted to the required zones")
	};
	(write, scope)
}

fn unknown() -> (Finding, Finding) {
	let finding =
		Finding::unknown("token policy shape cannot establish effective DNS grants and scope");
	(finding.clone(), finding)
}
