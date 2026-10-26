//! `epistle migrate mox`: read a Mox configuration directory (`mox.conf`
//! and `domains.conf`) into an import [`Plan`].
//!
//! Followed: the configuration reference of Mox v0.0.17 (`config/doc.go`
//! and `mox-/config.go` at that tag). `domains.conf` sits beside
//! `mox.conf`; a DKIM `PrivateKeyFile` is relative to that directory;
//! domain names are written in Unicode; a destination `@domain` is the
//! domain's catch-all; aliases live under each domain, keyed by local part.
//!
//! Account passwords are not in the configuration (Mox keeps them, hashed,
//! in its account database), so they cannot be carried over.

mod bounded;
#[cfg(test)]
pub(crate) mod fixture;
pub(crate) mod sconf;

use std::path::{Path, PathBuf};

use sconf::{Doc, Seg, path};

use super::import::{self, Account, Alias, Key, Plan, keys};

/// Why the configuration could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
	/// A file could not be read.
	#[error("reading {0}: {1}")]
	Io(PathBuf, std::io::Error),
	/// A file is not valid sconf.
	#[error("{0}: {1}")]
	Parse(PathBuf, sconf::SconfError),
}

/// Read the Mox configuration in `from` (the directory holding `mox.conf`,
/// or `mox.conf` itself).
pub(crate) fn read(from: &Path) -> Result<Plan, ReadError> {
	let dir = if from.is_file() {
		from.parent().unwrap_or(Path::new(".")).to_path_buf()
	} else {
		from.to_path_buf()
	};
	// mox.conf is read to confirm this is a Mox configuration; nothing in it
	// is imported (listeners, TLS and ACME are set up by `epistle init`).
	load(&dir.join("mox.conf"))?;
	let domains = load(&dir.join("domains.conf"))?;
	let mut plan = Plan {
		source: format!(
			"Mox configuration in {} (read as Mox v0.0.17 documents it)",
			dir.display()
		),
		..Plan::default()
	};
	for raw in domains.keys(&path(&["Domains"])) {
		read_domain(&domains, &dir, &raw, &mut plan);
	}
	for name in domains.keys(&path(&["Accounts"])) {
		read_account(&domains, &name, &mut plan);
	}
	// sconf maps have no order; sorted output reads the same every run.
	plan.domains.sort();
	plan.accounts.sort_by(|a, b| a.name.cmp(&b.name));
	plan.aliases.sort_by(|a, b| a.address.cmp(&b.address));
	plan.manual.push(
		"passwords: Mox keeps them hashed in its own database; each account is created \
		 disabled for login with a temporary or unknown password"
			.into(),
	);
	plan.manual.push(
		"mail: copy each account with `epistle migrate imap --account NAME --host OLD-SERVER \
		 --user ADDRESS`, then again after the DNS cutover"
			.into(),
	);
	Ok(plan)
}

fn load(file: &Path) -> Result<Doc, ReadError> {
	let text = read_bounded(file, sconf::MAX_BYTES).map_err(|e| ReadError::Io(file.into(), e))?;
	Doc::parse(&text).map_err(|e| ReadError::Parse(file.into(), e))
}

/// Read a regular UTF-8 file within 30 seconds and at most `limit` bytes.
pub(crate) fn read_bounded(file: &Path, limit: usize) -> std::io::Result<String> {
	bounded::read(file, limit)
}

fn read_domain(doc: &Doc, dir: &Path, raw: &str, plan: &mut Plan) {
	let Some(domain) = import::domain(raw) else {
		plan.skip(format!("domain {raw}"), "not a valid domain name");
		return;
	};
	plan.add_domain(&domain);
	let base = path(&["Domains", raw]);
	let dkim = [base.clone(), path(&["DKIM"])].concat();
	let signing = doc.list(&[dkim.clone(), path(&["Sign"])].concat());
	for selector in doc.keys(&[dkim.clone(), path(&["Selectors"])].concat()) {
		let at = [dkim.clone(), path(&["Selectors", &selector])].concat();
		let item = format!("DKIM selector {selector} of {domain}");
		if !signing.contains(&selector) {
			plan.skip(item, "Mox does not sign with it (not in Sign)");
			continue;
		}
		if !keys::valid_selector(&selector) {
			plan.skip(item, "not a valid DKIM selector");
			continue;
		}
		if doc.get(&[at.clone(), path(&["Hash"])].concat()) == Some("sha1") {
			plan.skip(item, "rsa-sha1 is no longer accepted by receivers");
			continue;
		}
		let Some(file) = doc.get(&[at, path(&["PrivateKeyFile"])].concat()) else {
			plan.skip(item, "no PrivateKeyFile");
			continue;
		};
		let file = dir.join(file);
		let key = read_bounded(&file, keys::MAX_KEY_BYTES)
			.map_err(|error| format!("reading {}: {error}", file.display()))
			.and_then(|pem| keys::normalize(&pem, None).map_err(|error| error.to_string()));
		match key {
			Ok(normalized) => plan.keys.push(Key {
				domain: domain.clone(),
				selector,
				algorithm: normalized.algorithm,
				pkcs8: normalized.pkcs8,
			}),
			Err(reason) => plan.skip(item, reason),
		}
	}
	for local in doc.keys(&[base.clone(), path(&["Aliases"])].concat()) {
		let at = [base.clone(), path(&["Aliases", &local])].concat();
		read_alias(doc, &at, &format!("{local}@{raw}"), plan);
	}
	for (section, what) in [
		("DMARC", "DMARC report address"),
		("TLSRPT", "TLS report address"),
		("MTASTS", "MTA-STS policy"),
	] {
		if doc
			.get(&[base.clone(), path(&[section])].concat())
			.is_some()
		{
			plan.manual.push(format!(
				"{domain}: the {what} configured in Mox is not imported; set it up in epistle \
				 (epistle dns-records lists what to publish)"
			));
		}
	}
}

fn read_alias(doc: &Doc, at: &[Seg], raw: &str, plan: &mut Plan) {
	let Some(address) = import::address(raw) else {
		plan.skip(format!("alias {raw}"), "not a valid address");
		return;
	};
	let mut members = Vec::new();
	for member in doc.list(&[at.to_vec(), path(&["Addresses"])].concat()) {
		match import::address(&member) {
			Some(member) => members.push(member),
			None => plan.skip(
				format!("member {member} of {address}"),
				"not a valid address",
			),
		}
	}
	if members.is_empty() {
		plan.skip(format!("alias {address}"), "no members");
		return;
	}
	let flag = |key: &str| doc.get(&[at.to_vec(), path(&[key])].concat()) == Some("true");
	if !flag("PostPublic") {
		plan.manual.push(format!(
			"alias {address}: Mox only let members post to it; epistle accepts mail to it from anyone"
		));
	}
	if !flag("AllowMsgFrom") {
		plan.manual.push(format!(
			"alias {address}: Mox did not let members send as it; epistle lets members send as it"
		));
	}
	plan.aliases.push(Alias {
		address,
		members,
		hidden: !flag("ListMembers"),
	});
}

fn read_account(doc: &Doc, raw_name: &str, plan: &mut Plan) {
	let name = crate::directory_store::account_name(raw_name);
	let base = path(&["Accounts", raw_name]);
	let default_domain = doc.get(&[base.clone(), path(&["Domain"])].concat());
	let mut account = Account {
		name: name.clone(),
		addresses: Vec::new(),
		catch_all: Vec::new(),
		display_name: doc
			.get(&[base.clone(), path(&["FullName"])].concat())
			.filter(|full| !full.is_empty())
			.map(str::to_string),
	};
	for destination in doc.keys(&[base.clone(), path(&["Destinations"])].concat()) {
		if let Some(catch_all) = destination.strip_prefix('@') {
			match import::domain(catch_all) {
				Some(domain) => account.catch_all.push(domain),
				None => plan.skip(format!("catch-all {destination}"), "not a valid domain"),
			}
			continue;
		}
		// A bare local part (deprecated in Mox) takes the account's domain.
		let full = match (destination.contains('@'), default_domain) {
			(true, _) => destination.clone(),
			(false, Some(domain)) => format!("{destination}@{domain}"),
			(false, None) => destination.clone(),
		};
		match import::address(&full) {
			Some(address) => account.addresses.push(address),
			None => plan.skip(
				format!("address {destination} of {name}"),
				"not a valid address",
			),
		}
		if account.display_name.is_none() {
			account.display_name = doc
				.get(
					&[
						base.clone(),
						path(&["Destinations", &destination, "FullName"]),
					]
					.concat(),
				)
				.filter(|full| !full.is_empty())
				.map(str::to_string);
		}
	}
	if let Err(reason) = import::account_name(&name) {
		plan.skip(format!("account {raw_name}"), reason);
		return;
	}
	if account.addresses.is_empty() {
		plan.skip(
			format!("account {name}"),
			"no address (epistle needs at least one)",
		);
		return;
	}
	if doc
		.get(&[base, path(&["LoginDisabled"])].concat())
		.is_some_and(|v| !v.is_empty())
	{
		plan.manual.push(format!(
			"account {name}: login was disabled in Mox; keep it disabled"
		));
	}
	plan.accounts.push(account);
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
