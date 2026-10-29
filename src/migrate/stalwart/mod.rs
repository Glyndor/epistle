//! `epistle migrate stalwart`: read a Stalwart `config.toml` into an import
//! [`Plan`].
//!
//! Followed: Stalwart v0.15.5, the last release configured by a TOML file
//! (`resources/config/config.toml`, `crates/directory/src/backend/memory/
//! config.rs` and `crates/common/src/config/smtp/auth.rs` at that tag).
//! From v0.16 the file only names the datastore and every setting lives in
//! the database; such a file is recognised and refused with directions.
//!
//! What a TOML file can hold, and is imported: DKIM signatures
//! (`[signature.<id>]` with `domain`, `selector`, `algorithm` and
//! `private-key`, inline PEM or `%{file:PATH}%`), and, when the directory in
//! use is the in-config `memory` type, its principals: individuals become
//! accounts, groups and mailing lists become aliases. An `internal`, `sql`
//! or `ldap` directory keeps accounts where this reader cannot safely go;
//! the plan then says how to move them.

use std::path::Path;

use toml::{Table, Value};

use super::import::{self, Account, Alias, Key, Plan, keys};
use super::mox::read_bounded;

#[cfg(test)]
pub(crate) mod fixture;

/// The largest configuration file read.
const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Why the configuration could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
	/// The file could not be read.
	#[error("reading {0}: {1}")]
	Io(String, std::io::Error),
	/// The file is not TOML.
	#[error("{0} is not a Stalwart TOML configuration: {1}")]
	Parse(String, String),
	/// A Stalwart 0.16 or later bootstrap file.
	#[error(
		"{0} is a Stalwart 0.16+ bootstrap file: every setting lives in Stalwart's database, \
		 not in a file. Create the domains and accounts here (epistle domain add, epistle \
		 account add), set up DKIM (epistle dkim), and copy each account's mail with \
		 epistle migrate imap"
	)]
	Database(String),
}

/// Read the Stalwart configuration at `file`.
pub(crate) fn read(file: &Path) -> Result<Plan, ReadError> {
	let shown = file.display().to_string();
	let text = read_bounded(file, MAX_BYTES).map_err(|e| ReadError::Io(shown.clone(), e))?;
	if text.trim_start().starts_with('{') {
		return Err(ReadError::Database(shown));
	}
	let table: Table = text
		.parse()
		.map_err(|e: toml::de::Error| ReadError::Parse(shown.clone(), e.message().to_string()))?;
	let dir = file.parent().unwrap_or(Path::new("."));
	let mut plan = Plan {
		source: format!("Stalwart configuration {shown} (read as Stalwart v0.15.5 defines it)"),
		..Plan::default()
	};
	read_signatures(&table, dir, &mut plan);
	read_directory(&table, &mut plan);
	plan.manual.push(
		"settings changed in Stalwart's web admin are stored in its database, not in this \
		 file, and are not imported"
			.into(),
	);
	plan.manual.push(
		"mail: copy each account with `epistle migrate imap --account NAME --host OLD-SERVER \
		 --user LOGIN`, then again after the DNS cutover"
			.into(),
	);
	Ok(plan)
}

/// The table at a dotted path of keys.
fn table_at<'a>(table: &'a Table, keys: &[&str]) -> Option<&'a Table> {
	keys.iter()
		.try_fold(table, |table, key| table.get(*key)?.as_table())
}

/// A string, or the strings of an array, at `key`.
fn strings(table: &Table, key: &str) -> Vec<String> {
	match table.get(key) {
		Some(Value::String(one)) => vec![one.clone()],
		Some(Value::Array(many)) => many
			.iter()
			.filter_map(Value::as_str)
			.map(str::to_string)
			.collect(),
		_ => Vec::new(),
	}
}

fn read_signatures(table: &Table, dir: &Path, plan: &mut Plan) {
	let Some(signatures) = table_at(table, &["signature"]) else {
		return;
	};
	for (id, signature) in signatures {
		let item = format!("DKIM signature {id}");
		let Some(signature) = signature.as_table() else {
			continue;
		};
		let text = |key: &str| signature.get(key).and_then(Value::as_str);
		let algorithm = match text("algorithm") {
			Some("ed25519-sha256") => keys::Algorithm::Ed25519,
			Some("rsa-sha256") => keys::Algorithm::Rsa,
			_ => {
				plan.skip(item, "algorithm is not ed25519-sha256 or rsa-sha256");
				continue;
			}
		};
		let (Some(raw_domain), Some(selector)) = (text("domain"), text("selector")) else {
			plan.skip(item, "no domain or selector");
			continue;
		};
		let Some(domain) = import::domain(raw_domain) else {
			plan.skip(item, "the domain is an expression or not a valid name");
			continue;
		};
		if !keys::valid_selector(selector) {
			plan.skip(item, "not a valid DKIM selector");
			continue;
		}
		let pem = match private_key(text("private-key").unwrap_or_default(), dir) {
			Ok(pem) => pem,
			Err(reason) => {
				plan.skip(item, reason);
				continue;
			}
		};
		match keys::normalize(&pem, Some(algorithm)) {
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

/// The PEM text of a `private-key` value: inline, or `%{file:PATH}%`
/// (relative to the configuration's directory).
fn private_key(value: &str, dir: &Path) -> Result<zeroize::Zeroizing<String>, String> {
	let value = value.trim();
	if let Some(file) = value
		.strip_prefix("%{file:")
		.and_then(|rest| rest.strip_suffix("}%"))
	{
		let path = dir.join(file);
		return read_bounded(&path, keys::MAX_KEY_BYTES)
			.map(zeroize::Zeroizing::new)
			.map_err(|error| format!("reading {}: {error}", path.display()));
	}
	if value.starts_with("%{") {
		return Err("the key comes from an environment variable or macro; copy it by hand".into());
	}
	Ok(zeroize::Zeroizing::new(value.to_string()))
}

fn read_directory(table: &Table, plan: &mut Plan) {
	let id = table_at(table, &["storage"])
		.and_then(|storage| storage.get("directory"))
		.and_then(Value::as_str)
		.unwrap_or("internal");
	let directory = table_at(table, &["directory", id]);
	let kind = directory
		.and_then(|d| d.get("type"))
		.and_then(Value::as_str)
		.unwrap_or("internal");
	if kind != "memory" {
		plan.manual.push(format!(
			"accounts: the directory in use (\"{id}\", type {kind}) keeps accounts outside this \
			 file. Create each one with `epistle account add NAME --address ADDRESS` and copy its \
			 mail with `epistle migrate imap`"
		));
		return;
	}
	let principals = directory
		.and_then(|d| d.get("principals"))
		.and_then(Value::as_array)
		.cloned()
		.unwrap_or_default();
	let principals: Vec<&Table> = principals.iter().filter_map(Value::as_table).collect();
	read_principals(&principals, plan);
	plan.manual.push(
		"passwords: Stalwart's are not carried over (epistle stores its own argon2id hashes); \
		 each account is created disabled for login with a temporary or unknown password"
			.into(),
	);
}

fn read_principals(principals: &[&Table], plan: &mut Plan) {
	let mut lists: Vec<(String, Vec<String>)> = Vec::new();
	let mut groups: Vec<(String, Vec<String>)> = Vec::new();
	let mut members_of: Vec<(String, String)> = Vec::new();
	for principal in principals {
		let Some(raw_name) = principal.get("name").and_then(Value::as_str) else {
			plan.skip("a principal", "no name");
			continue;
		};
		let class = principal
			.get("class")
			.and_then(Value::as_str)
			.unwrap_or("individual");
		let mut addresses = Vec::new();
		let mut catch_all = Vec::new();
		for email in strings(principal, "email") {
			if let Some(domain) = email.strip_prefix('@').and_then(import::domain) {
				plan.add_domain(&domain);
				catch_all.push(domain);
			} else if let Some(address) = import::address(&email) {
				plan.add_domain(address.rsplit_once('@').map_or("", |(_, d)| d));
				addresses.push(address);
			} else {
				plan.skip(
					format!("address {email} of {raw_name}"),
					"not a valid address",
				);
			}
		}
		if class == "group" {
			groups.push((raw_name.to_string(), addresses));
			continue;
		}
		let name = crate::directory_store::account_name(raw_name);
		if let Err(reason) = import::account_name(&name) {
			plan.skip(format!("account {raw_name}"), reason);
			continue;
		}
		let Some(primary) = addresses.first().cloned() else {
			plan.skip(
				format!("account {name}"),
				"no address (epistle needs at least one)",
			);
			continue;
		};
		for list in strings(principal, "email-list") {
			match import::address(&list) {
				Some(list) => match lists.iter_mut().find(|(address, _)| *address == list) {
					Some((_, members)) => members.push(primary.clone()),
					None => lists.push((list, vec![primary.clone()])),
				},
				None => plan.skip(format!("list {list}"), "not a valid address"),
			}
		}
		for group in strings(principal, "member-of") {
			members_of.push((group, primary.clone()));
		}
		if class == "admin" {
			plan.manual.push(format!(
				"account {name} was a Stalwart administrator; epistle administration is the CLI and API"
			));
		}
		plan.accounts.push(Account {
			name,
			addresses,
			catch_all,
			display_name: principal
				.get("description")
				.and_then(Value::as_str)
				.map(str::to_string),
		});
	}
	for (group, addresses) in groups {
		let members: Vec<String> = members_of
			.iter()
			.filter(|(name, _)| *name == group)
			.map(|(_, address)| address.clone())
			.collect();
		for address in addresses {
			if members.is_empty() {
				plan.skip(
					format!("group address {address}"),
					"the group has no members",
				);
				continue;
			}
			lists.push((address, members.clone()));
		}
	}
	for (address, members) in lists {
		plan.add_domain(address.rsplit_once('@').map_or("", |(_, d)| d));
		plan.aliases.push(Alias {
			address,
			members,
			hidden: true,
		});
	}
}

#[cfg(test)]
mod tests;
