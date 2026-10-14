//! `epistle domain`: list, show, add and remove configured domains;
//! add or remove a `domain_aliases` entry under the same parent command.
//!
//! `domain add` writes the new domain to `domains` and prints the DNS
//! records the operator now needs to publish. The DNS output mirrors
//! `dns-records` but scoped to the new domain only.
//!
//! `domain remove` refuses while any account (static config, dynamic
//! accounts, on-disk masked addresses), alias or `domain_aliases` entry
//! still uses the domain; the error lists the offenders so the operator
//! knows what to clean up first.

use std::io::Write;

use super::term::table::Table;
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::config::Config;

use super::config_edit::ConfigDocument;
use super::style;

#[path = "domain_dispatch.rs"]
mod dispatch;
use dispatch::{Outcome, execute};
#[derive(Debug, Subcommand)]
pub enum DomainCli {
	/// List every configured domain.
	List {
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Show one domain with its alias targets and reverse aliases.
	///
	/// Show one configured domain plus its alias targets and reverse aliases
	/// (other domains pointing at it).
	Show {
		/// The domain to show.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Add a domain and print the DNS records to publish.
	///
	/// Add a domain to `domains` and print the DNS records the operator now
	/// needs to publish.
	Add {
		/// Domain to add (e.g. `example.org`).
		#[arg(value_name = "DOMAIN")]
		domain: String,
	},
	/// Remove a domain from `domains`.
	///
	/// Refuses while the domain is still used by an account, alias, masked
	/// address or `domain_aliases` entry.
	Remove {
		/// Domain to remove.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Edit the `domain_aliases` map.
	Alias(DomainAliasArgs),
}

/// Sub-action on `epistle domain alias`.
#[derive(Debug, Args)]
pub struct DomainAliasArgs {
	#[command(subcommand)]
	pub action: DomainAliasSubcommand,
}

/// Add or remove a single `domain_aliases` entry.
#[derive(Debug, Subcommand)]
pub enum DomainAliasSubcommand {
	/// Make an alias domain resolve as a configured domain.
	Add {
		/// The alias domain.
		#[arg(value_name = "ALIAS")]
		alias: String,
		/// The target domain.
		#[arg(value_name = "TARGET")]
		target: String,
	},
	/// Drop a domain alias.
	Remove {
		/// The alias domain to drop.
		#[arg(value_name = "ALIAS")]
		alias: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

/// Run the chosen domain action.
pub(super) fn run(path: &Path, action: DomainCli, dry_run: bool) -> ExitCode {
	match execute(path, action, dry_run) {
		Outcome::Code(code) => code,
		Outcome::Error(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
		Outcome::Refusal(error) => {
			style::error(error);
			ExitCode::from(super::exit::REFUSED)
		}
	}
}

fn open(path: &Path) -> Result<ConfigDocument, String> {
	ConfigDocument::open(path)
}

#[derive(Serialize)]
struct DomainRow {
	domain: String,
	aliases_to: Vec<String>,
	aliases_from: Vec<String>,
}

/// List every configured domain plus its alias map. JSON-friendly.
pub(super) fn list(config: &Config, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	let mut rows = Vec::new();
	for domain in &config.domains {
		let aliases_to: Vec<String> = config
			.domain_aliases
			.iter()
			.filter(|(_, target)| target.eq_ignore_ascii_case(domain))
			.map(|(alias, _)| alias.clone())
			.collect();
		let aliases_from: Vec<String> = config
			.domain_aliases
			.iter()
			.filter(|(alias, _)| alias.eq_ignore_ascii_case(domain))
			.map(|(_, target)| target.clone())
			.collect();
		rows.push(DomainRow {
			domain: domain.clone(),
			aliases_to,
			aliases_from,
		});
	}
	if json {
		serde_json::to_writer(&mut *out, &rows).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	if let Some(decor) = super::term::stdout(json) {
		let mut table = Table::new(&["DOMAIN", "ALIASES TO", "ALIASES FROM"]);
		for row in &rows {
			let joined = |list: &[String]| {
				if list.is_empty() {
					"-".into()
				} else {
					list.join(",")
				}
			};
			table.push(vec![
				row.domain.clone(),
				joined(&row.aliases_to),
				joined(&row.aliases_from),
			]);
		}
		return table.write(decor, out);
	}
	writeln!(out, "{:<30} ALIASES TO   ALIASES FROM", "DOMAIN")?;
	for row in &rows {
		writeln!(
			out,
			"{:<30} {:<12} {}",
			row.domain,
			if row.aliases_to.is_empty() {
				"-".into()
			} else {
				row.aliases_to.join(",")
			},
			if row.aliases_from.is_empty() {
				"-".into()
			} else {
				row.aliases_from.join(",")
			},
		)?;
	}
	Ok(())
}

#[derive(Serialize)]
struct DomainView {
	domain: String,
	aliases_to: Vec<String>,
	aliases_from: Vec<String>,
	accounts: Vec<String>,
	aliases: Vec<String>,
}

/// Show one domain: alias edges plus the local accounts and aliases that
/// rely on it.
fn show(config: &Config, domain: &str, json: bool, out: &mut impl Write) -> std::io::Result<()> {
	if !config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(domain))
	{
		return Err(std::io::Error::other(format!(
			"domain {domain} is not configured"
		)));
	}
	let aliases_to: Vec<String> = config
		.domain_aliases
		.iter()
		.filter(|(_, target)| target.eq_ignore_ascii_case(domain))
		.map(|(alias, _)| alias.clone())
		.collect();
	let aliases_from: Vec<String> = config
		.domain_aliases
		.iter()
		.filter(|(alias, _)| alias.eq_ignore_ascii_case(domain))
		.map(|(_, target)| target.clone())
		.collect();
	let accounts: Vec<String> = config
		.accounts
		.iter()
		.flat_map(|account| account.addresses.iter())
		.filter(|address| {
			crate::smtp::address::Address::parse(address)
				.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
				.unwrap_or(false)
		})
		.cloned()
		.collect();
	let aliases: Vec<String> = config
		.alias
		.iter()
		.filter(|alias| {
			crate::smtp::address::Address::parse(&alias.address)
				.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
				.unwrap_or(false)
		})
		.map(|alias| alias.address.clone())
		.collect();
	let view = DomainView {
		domain: domain.to_string(),
		aliases_to,
		aliases_from,
		accounts,
		aliases,
	};
	if json {
		serde_json::to_writer(&mut *out, &view).map_err(std::io::Error::other)?;
		writeln!(out)?;
		return Ok(());
	}
	writeln!(out, "domain\t{}", view.domain)?;
	writeln!(
		out,
		"aliases_to\t{}",
		if view.aliases_to.is_empty() {
			"-".into()
		} else {
			view.aliases_to.join(",")
		}
	)?;
	writeln!(
		out,
		"aliases_from\t{}",
		if view.aliases_from.is_empty() {
			"-".into()
		} else {
			view.aliases_from.join(",")
		}
	)?;
	writeln!(
		out,
		"accounts\t{}",
		if view.accounts.is_empty() {
			"-".into()
		} else {
			view.accounts.join(",")
		}
	)?;
	writeln!(
		out,
		"aliases\t{}",
		if view.aliases.is_empty() {
			"-".into()
		} else {
			view.aliases.join(",")
		}
	)?;
	Ok(())
}

/// Validate `domain` as a DNS name and check it is not already configured.
fn validate_domain_for_add(config: &Config, raw: &str) -> Result<(), String> {
	crate::config::validate_dns_name("domain", raw).map_err(|e| e.to_string())?;
	if config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(raw))
	{
		return Err(format!("domain {raw} is already configured"));
	}
	// A new domain must not collide with an existing alias source or
	// target. Allowing it would silently re-route mail that resolves
	// through domain_aliases.
	for (alias, target) in &config.domain_aliases {
		if alias.eq_ignore_ascii_case(raw) {
			return Err(format!(
				"domain {raw} is already declared as a domain alias (target {target})"
			));
		}
		if target.eq_ignore_ascii_case(raw) {
			return Err(format!(
				"domain {raw} is already targeted by the domain alias {alias}"
			));
		}
	}
	Ok(())
}

/// Add `domain` to the `domains` array.
fn add_domain(config: &Config, document: &mut ConfigDocument, domain: &str) -> Result<(), String> {
	validate_domain_for_add(config, domain)?;
	let mut domains = config.domains.clone();
	domains.push(domain.trim().to_ascii_lowercase());
	let mut new_array = toml_edit::Array::new();
	for existing in &domains {
		new_array.push(toml_edit::Value::from(existing.clone()));
	}
	document.replace_top_array("domains", new_array)?;
	Ok(())
}

/// Refuse the removal when `domain` is in use. Returns the user-facing
/// message listing each offender category and the addresses themselves.
fn remove_domain(
	config: &Config,
	document: &mut ConfigDocument,
	domain: &str,
) -> Result<(), String> {
	if !config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(domain))
	{
		return Err(format!("domain {domain} is not configured"));
	}
	removal_blockers(config, domain)?;
	let remaining: Vec<String> = config
		.domains
		.iter()
		.filter(|existing| !existing.eq_ignore_ascii_case(domain))
		.cloned()
		.collect();
	let mut new_array = toml_edit::Array::new();
	for existing in &remaining {
		new_array.push(toml_edit::Value::from(existing.clone()));
	}
	document.replace_top_array("domains", new_array)?;
	Ok(())
}

fn add_alias_map(
	config: &Config,
	document: &mut ConfigDocument,
	alias: &str,
	target: &str,
) -> Result<(), String> {
	crate::config::validate_dns_name("domain alias", alias).map_err(|e| e.to_string())?;
	crate::config::validate_dns_name("domain alias target", target).map_err(|e| e.to_string())?;
	if !config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(target))
	{
		return Err(format!(
			"domain alias target {target} is not a configured domain"
		));
	}
	if config.domain_aliases.iter().any(|(existing, _)| {
		existing.eq_ignore_ascii_case(alias) || alias.eq_ignore_ascii_case(existing)
	}) {
		return Err(format!("domain alias {alias} is already declared"));
	}
	if config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(alias))
	{
		return Err(format!(
			"domain alias {alias} collides with a configured domain"
		));
	}
	let (alias, target) = (
		alias.trim().to_ascii_lowercase(),
		target.trim().to_ascii_lowercase(),
	);
	document.set_map_entry("domain_aliases", &alias, target)?;
	Ok(())
}

fn remove_alias_map(
	config: &Config,
	document: &mut ConfigDocument,
	alias: &str,
) -> Result<(), String> {
	if !config
		.domain_aliases
		.iter()
		.any(|(existing, _)| existing.eq_ignore_ascii_case(alias))
	{
		return Err(format!("domain alias {alias} is not declared"));
	}
	let key = document
		.map_key("domain_aliases", |key| {
			key.eq_ignore_ascii_case(alias.trim())
		})
		.unwrap_or_else(|| alias.to_string());
	document.remove_map_entry("domain_aliases", &key)?;
	Ok(())
}

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "domain_tests_aliases.rs"]
mod tests_aliases;
#[cfg(test)]
#[path = "domain_tests_dry_run.rs"]
mod tests_dry_run;
#[cfg(test)]
#[path = "domain_tests_removal.rs"]
mod tests_removal;
#[cfg(test)]
#[path = "domain_tests_unknown.rs"]
mod tests_unknown;

#[path = "domain_blockers.rs"]
pub mod domain_blockers;
pub(super) use domain_blockers::removal_blockers;

#[path = "domain_writers.rs"]
pub mod domain_writers;
