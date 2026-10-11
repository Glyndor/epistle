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
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::config::Config;

use super::config_edit::{ConfigDocument, Outcome};
use super::style;

/// Domain administration actions.
#[derive(Debug, Subcommand)]
pub enum DomainCli {
	/// List every configured domain.
	List {
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Show one configured domain plus its alias targets and reverse
	/// aliases (other domains pointing at it).
	Show {
		/// The domain to show.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Emit JSON instead of the human-readable table.
		#[arg(long)]
		json: bool,
	},
	/// Add a domain to `domains` and print the DNS records the operator
	/// now needs to publish.
	Add {
		/// Domain to add (e.g. `example.org`).
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Print the validated diff without writing or restarting.
		#[arg(long)]
		dry_run: bool,
	},
	/// Remove a domain from `domains`. Refuses while the domain is still
	/// used by an account, alias, masked address or `domain_aliases` entry.
	Remove {
		/// Domain to remove.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Print the validated diff without writing or restarting.
		#[arg(long)]
		dry_run: bool,
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
	Add {
		/// The alias domain.
		#[arg(value_name = "ALIAS")]
		alias: String,
		/// The target domain.
		#[arg(value_name = "TARGET")]
		target: String,
	},
	Remove {
		/// The alias domain to drop.
		#[arg(value_name = "ALIAS")]
		alias: String,
	},
}

/// Run the chosen domain action.
pub(super) fn run(path: &Path, action: DomainCli) -> ExitCode {
	match execute(path, action) {
		Ok(code) => code,
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

fn execute(path: &Path, action: DomainCli) -> Result<ExitCode, String> {
	let mut out = std::io::stdout().lock();
	let mut err = style::stderr();
	let config = Config::load(path).map_err(|e| e.to_string())?;
	match action {
		DomainCli::List { json } => {
			list(&config, json, &mut out).map_err(|e| e.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		DomainCli::Show { domain, json } => {
			show(&config, &domain, json, &mut out).map_err(|e| e.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		DomainCli::Add { domain, dry_run } => {
			let mut document = open(path)?;
			add_domain(&config, &mut document, &domain)?;
			commit_add(&config, document, &domain, dry_run, &mut out, &mut err)
		}
		DomainCli::Remove { domain, dry_run } => {
			let mut document = open(path)?;
			remove_domain(&config, &mut document, &domain)?;
			commit_remove(document, &domain, dry_run, &mut out, &mut err)
		}
		DomainCli::Alias(args) => match args.action {
			DomainAliasSubcommand::Add { alias, target } => {
				let mut document = open(path)?;
				let owned_alias = alias.clone();
				add_alias_map(&config, &mut document, &alias, &target)?;
				commit_and_restart(document, &owned_alias, "added", false, &mut out, &mut err)
			}
			DomainAliasSubcommand::Remove { alias } => {
				let mut document = open(path)?;
				let owned_alias = alias.clone();
				remove_alias_map(&config, &mut document, &alias)?;
				commit_and_restart(document, &owned_alias, "removed", false, &mut out, &mut err)
			}
		},
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
fn list(config: &Config, json: bool, out: &mut impl Write) -> std::io::Result<()> {
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
	domains.push(domain.to_string());
	let mut new_array = toml_edit::Array::new();
	for existing in &domains {
		new_array.push(toml_edit::Value::from(existing.clone()));
	}
	document.replace_top_array("domains", new_array)?;
	Ok(())
}

/// Refuse the removal when `domain` is in use. Returns the user-facing
/// message listing each offender category and the addresses themselves.
fn removal_blockers(config: &Config, domain: &str) -> Result<(), String> {
	let mut offenders: Vec<String> = Vec::new();
	// Static accounts.
	for account in &config.accounts {
		for address in &account.addresses {
			if address_domain_matches(address, domain) {
				offenders.push(format!("account {} uses {address}", account.name));
			}
		}
	}
	// Aliases.
	for alias in &config.alias {
		if address_domain_matches(&alias.address, domain) {
			offenders.push(format!("alias {} uses the domain", alias.address));
		}
		for member in &alias.members {
			if address_domain_matches(member, domain) {
				offenders.push(format!("alias {} has member {member}", alias.address));
			}
		}
		for sender in &alias.senders {
			if address_domain_matches(sender, domain) {
				offenders.push(format!("alias {} allows sender {sender}", alias.address));
			}
		}
	}
	// domain_aliases map.
	for (alias, target) in &config.domain_aliases {
		if alias.eq_ignore_ascii_case(domain) {
			offenders.push(format!("domain_aliases has {alias} -> {target}"));
		}
		if target.eq_ignore_ascii_case(domain) {
			offenders.push(format!("domain_aliases maps {alias} to {domain}"));
		}
	}
	// Masked addresses (on disk).
	let masked_path = config.data_dir.join("masked.json");
	if let Ok(text) = std::fs::read_to_string(&masked_path) {
		if let Ok(file) = serde_json::from_str::<serde_json::Value>(&text) {
			if let Some(addresses) = file.get("addresses").and_then(|v| v.as_object()) {
				for (key, value) in addresses {
					if address_domain_matches(key, domain) {
						let owner = value.get("account").and_then(|v| v.as_str()).unwrap_or("?");
						offenders.push(format!("masked address {key} (account {owner})"));
					}
				}
			}
		}
	}
	// Dynamic accounts (data_dir/accounts.toml).
	let accounts_path = config.data_dir.join("accounts.toml");
	if let Ok(text) = std::fs::read_to_string(&accounts_path) {
		if let Ok(file) = toml::from_str::<toml::Value>(&text) {
			if let Some(accounts) = file.get("accounts").and_then(|v| v.as_array()) {
				for account in accounts {
					let name = account.get("name").and_then(|v| v.as_str()).unwrap_or("?");
					if let Some(addresses) = account.get("addresses").and_then(|v| v.as_array()) {
						for address in addresses {
							if let Some(address) = address.as_str() {
								if address_domain_matches(address, domain) {
									offenders
										.push(format!("dynamic account {name} uses {address}"));
								}
							}
						}
					}
				}
			}
		}
	}
	if offenders.is_empty() {
		Ok(())
	} else {
		offenders.sort();
		offenders.dedup();
		Err(format!(
			"domain {domain} is still in use: {}",
			offenders.join(", ")
		))
	}
}

fn address_domain_matches(address: &str, domain: &str) -> bool {
	crate::smtp::address::Address::parse(address)
		.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
		.unwrap_or(false)
}

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
	document.set_map_entry("domain_aliases", alias, target.to_string())?;
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
	document.remove_map_entry("domain_aliases", alias)?;
	Ok(())
}

fn commit_and_restart(
	document: ConfigDocument,
	alias: &str,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	if outcome == Outcome::Unchanged {
		writeln!(
			status,
			"domain alias {alias} already {verb}; nothing changed."
		)
		.map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain alias {alias} {verb}.").map_err(|e| e.to_string())?;
	super::config_edit::after_change_with(&config, outcome, true, status, super::stack::run)
}

/// Validate-and-commit for `domain add`: the helper unwraps the new
/// domain so `add_domain` can return early on a bad name, then the
/// commit step prints the DNS records the operator must publish.
fn commit_add(
	_config: &Config,
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let new_config = document.config()?;
	let outcome = document.commit()?;
	if outcome == Outcome::Unchanged {
		writeln!(
			status,
			"domain {domain} already configured; nothing changed."
		)
		.map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain {domain} added.").map_err(|e| e.to_string())?;
	print_domain_records(&new_config, domain, out).map_err(|e| e.to_string())?;
	super::config_edit::after_change_with(&new_config, outcome, true, status, super::stack::run)
}

fn commit_remove(
	document: ConfigDocument,
	domain: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	if outcome == Outcome::Unchanged {
		writeln!(status, "domain {domain} already removed; nothing changed.")
			.map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "domain {domain} removed.").map_err(|e| e.to_string())?;
	let _ = config;
	super::config_edit::after_change_with(&config, outcome, true, status, super::stack::run)
}

/// Print the DNS records `dns-records` would emit, restricted to the new
/// `domain`. Mirrors `crate::cli::dns_records::run` so the operator sees
/// the same shape they would on a full run.
fn print_domain_records(
	config: &Config,
	domain: &str,
	out: &mut impl Write,
) -> std::io::Result<()> {
	let dkim_owned: Vec<(String, String)> = config
		.dkim
		.as_ref()
		.map(|dkim| {
			let mut pairs = Vec::new();
			if let Ok(signer) = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file) {
				pairs.push((dkim.selector.clone(), signer.dns_record_value()));
			}
			pairs
		})
		.unwrap_or_default();
	let tlsa = config
		.tls
		.as_ref()
		.and_then(|tls| std::fs::read_to_string(&tls.cert_file).ok())
		.and_then(|pem| crate::dns::records::tlsa_full_cert(&pem));
	let recs = crate::dns::records::build_records(
		&[domain.to_string()],
		&config.hostname,
		&dkim_owned,
		tlsa.as_deref(),
		&crate::dns::records::mta_sts_id(config),
		crate::dns::records::Services::all(),
		config.acme.as_ref().map(|a| a.directory_url.as_str()),
		config.public_ipv4,
		config.public_ipv6,
	);
	writeln!(out, "\nDNS records to publish for {domain}:")?;
	for entry in &recs {
		let r = &entry.record;
		let value = match r.kind {
			crate::dns::provider::RecordKind::Txt => crate::dns::records::txt_zone_form(&r.value),
			_ => r.value.clone(),
		};
		writeln!(out, "{} {} IN {} {}", r.name, r.ttl, r.kind.as_str(), value)?;
	}
	Ok(())
}

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "domain_tests_aliases.rs"]
mod tests_aliases;
#[cfg(test)]
#[path = "domain_tests_removal.rs"]
mod tests_removal;
