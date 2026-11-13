//! Reading a Stalwart 0.16+ plan file (NDJSON, one operation per line, the
//! shape `stalwart-cli snapshot` prints and `stalwart-cli apply` takes).
//!
//! From 0.16 the settings live in Stalwart's database as typed objects, so
//! nothing is read from its files or its store: the operator exports the
//! objects through Stalwart's own management tool and epistle reads that
//! file. The format is the one Stalwart documents for plan files: each line
//! is `{"@type":"upsert","object":"Domain","matchOn":[...],"value":{ID:{...}}}`,
//! values are keyed by client ids and other objects refer to them as `#ID`;
//! sets and lists are JSON objects (sets `{"a@b":true}`, lists `{"0":{...}}`).
//!
//! Imported: domains, user accounts with their aliases, groups and mailing
//! lists (as aliases), a domain's catch-all address, and the active DKIM
//! signatures whose private key is in the file. Never imported: passwords
//! (epistle keeps its own argon2id hashes), settings, rules, listeners,
//! certificates, tenants, roles.

mod objects;

use serde_json::Value;

use super::super::import::Plan;

/// The operations a plan file holds.
const OPERATIONS: [&str; 5] = ["upsert", "reconcile", "create", "update", "destroy"];

/// Whether `text` is a plan file rather than a 0.16 bootstrap `config.json`.
pub(super) fn is_plan(text: &str) -> bool {
	text.lines()
		.find(|line| !line.trim().is_empty())
		.and_then(|line| serde_json::from_str::<Value>(line).ok())
		.and_then(|value| value.get("@type")?.as_str().map(str::to_string))
		.is_some_and(|kind| OPERATIONS.contains(&kind.as_str()))
}

/// The objects of a plan file, by type, in file order.
#[derive(Default)]
pub(super) struct Objects {
	pub(super) domains: Vec<(String, Value)>,
	pub(super) accounts: Vec<(String, Value)>,
	pub(super) lists: Vec<(String, Value)>,
	pub(super) signatures: Vec<(String, Value)>,
}

/// Read the plan file `text` into an import [`Plan`].
pub(super) fn read(text: &str, shown: &str) -> Result<Plan, String> {
	let mut objects = Objects::default();
	let mut ignored: Vec<String> = Vec::new();
	for (number, line) in text.lines().enumerate() {
		if line.trim().is_empty() {
			continue;
		}
		let value: Value = serde_json::from_str(line)
			.map_err(|error| format!("line {}: not JSON ({error})", number + 1))?;
		let kind = value.get("@type").and_then(Value::as_str).unwrap_or("");
		if !OPERATIONS.contains(&kind) {
			return Err(format!("line {}: not a plan operation", number + 1));
		}
		let name = value.get("object").and_then(Value::as_str).unwrap_or("");
		let name = name.trim_start_matches("x:").to_ascii_lowercase();
		let entries = match (kind, value.get("value").and_then(Value::as_object)) {
			("upsert" | "create" | "reconcile", Some(map)) => map,
			_ => {
				note_ignored(&mut ignored, &name);
				continue;
			}
		};
		let target = match name.as_str() {
			"domain" => &mut objects.domains,
			"account" => &mut objects.accounts,
			"mailinglist" => &mut objects.lists,
			"dkimsignature" => &mut objects.signatures,
			_ => {
				note_ignored(&mut ignored, &name);
				continue;
			}
		};
		for (id, entry) in entries {
			target.push((id.trim_start_matches('#').to_string(), entry.clone()));
		}
	}
	let mut plan = Plan {
		source: format!("Stalwart plan file {shown} (Stalwart 0.16 or later)"),
		..Plan::default()
	};
	objects::fill(&objects, &mut plan);
	if !ignored.is_empty() {
		ignored.sort();
		ignored.dedup();
		plan.manual.push(format!(
			"not imported, by design: {} (settings, rules and listeners are not carried over)",
			ignored.join(", ")
		));
	}
	plan.manual.push(
		"passwords: Stalwart's are not carried over (epistle stores its own argon2id hashes); \
		 each account is created disabled for login with a temporary or unknown password"
			.into(),
	);
	plan.manual.push(
		"mail: copy each account with `epistle migrate imap --account NAME --host OLD-SERVER \
		 --user LOGIN`, then again after the DNS cutover"
			.into(),
	);
	Ok(plan)
}

fn note_ignored(ignored: &mut Vec<String>, name: &str) {
	if !name.is_empty() {
		ignored.push(name.to_string());
	}
}

#[cfg(test)]
mod tests;
