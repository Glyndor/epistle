//! Turning the collected plan objects into an import plan.

use std::collections::HashMap;

use serde_json::Value;

use super::Objects;
use crate::migrate::import::{self, Account, Alias, Key, Plan, keys};

/// The text of `key`, when it is a string.
fn text<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
	object.get(key)?.as_str()
}

/// The members of a set: `{"a":true}` keys, or the strings of an array.
fn set(object: &Value, key: &str) -> Vec<String> {
	match object.get(key) {
		Some(Value::Object(map)) => map
			.iter()
			.filter(|(_, on)| on.as_bool() != Some(false))
			.map(|(member, _)| member.clone())
			.collect(),
		Some(Value::Array(items)) => items
			.iter()
			.filter_map(Value::as_str)
			.map(str::to_string)
			.collect(),
		_ => Vec::new(),
	}
}

/// The entries of a list: the values of `{"0":{...}}`, or an array's items.
fn list<'a>(object: &'a Value, key: &str) -> Vec<&'a Value> {
	match object.get(key) {
		Some(Value::Object(map)) => map.values().collect(),
		Some(Value::Array(items)) => items.iter().collect(),
		_ => Vec::new(),
	}
}

/// The domain names by client id.
type Domains = HashMap<String, String>;

/// The domain an object's `domainId` refers to.
fn domain_of(object: &Value, domains: &Domains) -> Option<String> {
	let id = text(object, "domainId")?.trim_start_matches('#');
	domains.get(id).cloned()
}

/// `name@domain` of an object, or of one of its alias entries.
fn address_of(object: &Value, domains: &Domains) -> Option<String> {
	let domain = domain_of(object, domains)?;
	import::address(&format!("{}@{domain}", text(object, "name")?))
}

/// The extra addresses of an object: its enabled aliases.
fn aliases_of(object: &Value, domains: &Domains) -> Vec<String> {
	list(object, "aliases")
		.into_iter()
		.filter(|alias| alias.get("enable").and_then(Value::as_bool) != Some(false))
		.filter_map(|alias| address_of(alias, domains))
		.collect()
}

fn domain_part(address: &str) -> &str {
	address.rsplit_once('@').map_or("", |(_, domain)| domain)
}

pub(super) fn fill(objects: &Objects, plan: &mut Plan) {
	let mut domains = Domains::new();
	let mut catch_alls: Vec<(String, String)> = Vec::new();
	for (id, domain) in &objects.domains {
		let raw = text(domain, "name").unwrap_or_default();
		let Some(name) = import::domain(raw) else {
			plan.skip(format!("domain {raw}"), "not a valid domain name");
			continue;
		};
		plan.add_domain(&name);
		domains.insert(id.clone(), name.clone());
		if domain.get("enable").and_then(Value::as_bool) == Some(false) {
			plan.manual.push(format!(
				"domain {name} is disabled in Stalwart; it is imported enabled"
			));
		}
		if !set(domain, "aliases").is_empty() {
			plan.manual.push(format!(
				"domain {name} has alias domains in Stalwart; add their addresses to each account \
				 by hand"
			));
		}
		if let Some(address) = text(domain, "catchAllAddress").and_then(import::address) {
			catch_alls.push((name, address));
		}
	}
	let (groups, memberships) = accounts(objects, &domains, plan);
	groups_to_aliases(&groups, &memberships, plan);
	lists(objects, &domains, plan);
	for (domain, address) in catch_alls {
		match plan
			.accounts
			.iter_mut()
			.find(|a| a.addresses.contains(&address))
		{
			Some(account) => account.catch_all.push(domain),
			None => plan.skip(
				format!("catch-all of {domain}"),
				format!("{address} is not an imported account"),
			),
		}
	}
	signatures(objects, &domains, plan);
}

/// A group: its addresses and its client id.
struct Group {
	id: String,
	addresses: Vec<String>,
}

/// Which users belong to which groups: `(group id, user's primary address)`.
type Memberships = Vec<(String, String)>;

fn accounts(objects: &Objects, domains: &Domains, plan: &mut Plan) -> (Vec<Group>, Memberships) {
	let mut groups = Vec::new();
	let mut memberships = Memberships::new();
	for (id, account) in &objects.accounts {
		let kind = text(account, "@type").unwrap_or("User");
		let raw = text(account, "name").unwrap_or_default();
		let mut addresses: Vec<String> = address_of(account, domains).into_iter().collect();
		addresses.extend(aliases_of(account, domains));
		if kind == "Group" {
			groups.push(Group {
				id: id.clone(),
				addresses,
			});
			continue;
		}
		let name = crate::directory_store::account_name(raw);
		if let Err(reason) = import::account_name(&name) {
			plan.skip(format!("account {raw}"), reason);
			continue;
		}
		let Some(primary) = addresses.first().cloned() else {
			plan.skip(
				format!("account {name}"),
				"no address: its domain is not in the file (add Domain to the snapshot)",
			);
			continue;
		};
		for group in set(account, "memberGroupIds") {
			memberships.push((group.trim_start_matches('#').to_string(), primary.clone()));
		}
		if account.get("roles").and_then(|roles| text(roles, "@type")) == Some("Admin") {
			plan.manual.push(format!(
				"account {name} was a Stalwart administrator; epistle administration is the CLI and API"
			));
		}
		plan.accounts.push(Account {
			name,
			addresses,
			catch_all: Vec::new(),
			display_name: text(account, "description").map(str::to_string),
		});
	}
	(groups, memberships)
}

fn groups_to_aliases(groups: &[Group], memberships: &Memberships, plan: &mut Plan) {
	for group in groups {
		let members: Vec<String> = memberships
			.iter()
			.filter(|(id, _)| *id == group.id)
			.map(|(_, member)| member.clone())
			.collect();
		for address in &group.addresses {
			if members.is_empty() {
				plan.skip(
					format!("group address {address}"),
					"the group has no members",
				);
				continue;
			}
			plan.add_domain(domain_part(address));
			plan.aliases.push(Alias {
				address: address.clone(),
				members: members.clone(),
				hidden: true,
			});
		}
	}
}

fn lists(objects: &Objects, domains: &Domains, plan: &mut Plan) {
	for (_, entry) in &objects.lists {
		let raw = text(entry, "name").unwrap_or_default();
		let mut addresses: Vec<String> = address_of(entry, domains).into_iter().collect();
		addresses.extend(aliases_of(entry, domains));
		let mut members = Vec::new();
		for recipient in set(entry, "recipients") {
			match import::address(&recipient) {
				Some(address) => members.push(address),
				None => plan.skip(
					format!("recipient {recipient} of list {raw}"),
					"not a valid address",
				),
			}
		}
		if addresses.is_empty() || members.is_empty() {
			plan.skip(
				format!("mailing list {raw}"),
				"no address in an imported domain, or no recipients",
			);
			continue;
		}
		for address in addresses {
			plan.add_domain(domain_part(&address));
			plan.aliases.push(Alias {
				address,
				members: members.clone(),
				hidden: true,
			});
		}
	}
}

fn signatures(objects: &Objects, domains: &Domains, plan: &mut Plan) {
	for (_, signature) in &objects.signatures {
		let selector = text(signature, "selector").unwrap_or_default();
		let item = format!("DKIM signature {selector}");
		let algorithm = match text(signature, "@type") {
			Some("Dkim1Ed25519Sha256") => keys::Algorithm::Ed25519,
			Some("Dkim1RsaSha256") => keys::Algorithm::Rsa,
			_ => {
				plan.skip(item, "not a DKIM1 ed25519-sha256 or rsa-sha256 signature");
				continue;
			}
		};
		if text(signature, "stage").is_some_and(|stage| stage != "active") {
			plan.skip(item, "not the active key of a rotation");
			continue;
		}
		let Some(domain) = domain_of(signature, domains) else {
			plan.skip(
				item,
				"its domain is not in the file (add Domain to the snapshot)",
			);
			continue;
		};
		if !keys::valid_selector(selector) {
			plan.skip(item, "not a valid DKIM selector");
			continue;
		}
		let pem = match signature.get("privateKey") {
			Some(key) if text(key, "@type") == Some("Text") => text(key, "secret"),
			Some(_) => {
				plan.skip(
					item,
					"the key is read from a file or variable; copy it by hand",
				);
				continue;
			}
			None => None,
		};
		let Some(pem) = pem.filter(|pem| *pem != "****") else {
			plan.skip(
				item,
				"no private key in the file: Stalwart leaves secrets out unless the snapshot is \
				 taken with --include-secrets",
			);
			continue;
		};
		match keys::normalize(pem, Some(algorithm)) {
			Ok(normalized) => {
				plan.add_domain(&domain);
				plan.keys.push(Key {
					domain,
					selector: selector.to_string(),
					algorithm,
					pkcs8: normalized.pkcs8,
				});
			}
			Err(error) => plan.skip(item, error.to_string()),
		}
	}
}
