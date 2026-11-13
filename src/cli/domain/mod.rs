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

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config::Config;

use super::config_edit::ConfigDocument;
use super::style;

pub(in crate::cli) mod own_key;
mod role;
mod set;
mod state;
mod view;
pub(in crate::cli) use view::list;
use view::show;

mod dispatch;
use dispatch::{Outcome, execute};

/// Domain administration actions.
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
	/// needs to publish. With `[dkim]` configured the domain gets a DKIM key
	/// of its own, written under `keys/dkim/<domain>/` and named by a
	/// `[[dkim.domain]]` entry, so the records include its selector.
	Add {
		/// Domain to add (e.g. `example.org`).
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Sign this domain with the `[dkim]` key instead of a key of its
		/// own. The key then signs as every domain that shares it.
		#[arg(long)]
		shared_dkim_key: bool,
		/// The domain only sends mail: its DNS carries SPF, DKIM, DMARC and
		/// MX, and no MTA-STS, TLS-RPT, SRV, autoconfig or autodiscover record.
		#[arg(long, conflicts_with = "receive_only")]
		send_only: bool,
		/// The domain only receives mail: nothing is sent as it, so its DNS
		/// carries the null SPF, a `reject` DMARC policy and no DKIM key.
		#[arg(long)]
		receive_only: bool,
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
	/// Set the role, storage quota or submission rate of one domain.
	///
	/// The quota and rate are the per-domain overrides `limits set --domain`
	/// writes. A flag that is left out keeps its value; `--no-quota` and
	/// `--no-submission-rate` remove the override. `--send-only`,
	/// `--receive-only` and `--full` change the role: which DNS records the
	/// domain needs and who may send as it.
	#[command(group(clap::ArgGroup::new("change").required(true).multiple(true)
		.args(["quota", "no_quota", "submission_rate", "no_submission_rate", "send_only", "receive_only", "full"])))]
	Set {
		/// Domain to change.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Default storage quota of the accounts in the domain (for example 10G).
		#[arg(long, value_name = "SIZE", conflicts_with = "no_quota")]
		quota: Option<String>,
		/// Remove the domain's quota override.
		#[arg(long)]
		no_quota: bool,
		/// Messages per minute an authenticated sender in the domain may submit.
		#[arg(
			long,
			value_name = "N",
			conflicts_with = "no_submission_rate",
			allow_hyphen_values = true
		)]
		submission_rate: Option<String>,
		/// Remove the domain's submission rate override.
		#[arg(long)]
		no_submission_rate: bool,
		/// The domain only sends mail: SPF, DKIM, DMARC and MX, nothing
		/// else in DNS.
		#[arg(long, conflicts_with_all = ["full", "receive_only"])]
		send_only: bool,
		/// The domain only receives mail: the null SPF, a `reject` DMARC
		/// policy, no DKIM key, and nobody may send as it.
		#[arg(long, conflicts_with = "full")]
		receive_only: bool,
		/// The domain receives mail and sets clients up: every record
		/// (the default role).
		#[arg(long)]
		full: bool,
	},
	/// Switch a domain off without removing it.
	///
	/// Mail for the domain is rejected like mail for an unknown user and
	/// nobody may send as an address in it. Accounts, mailboxes, DNS
	/// records and DKIM keys stay. Undo it with `domain enable`.
	Disable {
		/// Domain to switch off.
		#[arg(value_name = "DOMAIN")]
		domain: String,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Switch a disabled domain back on.
	Enable {
		/// Domain to switch on.
		#[arg(value_name = "DOMAIN")]
		domain: String,
	},
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
pub(super) fn run(path: &Path, action: DomainCli, dry_run: bool, json: bool) -> ExitCode {
	match execute(path, action, dry_run, json) {
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
	// The domain signs the sender of what it forwards with a secret of its
	// own from the start, never with one shared with the others.
	let secret = crate::queue::srs::generate_secret()
		.ok_or("the system gave no random bytes for the domain's SRS secret")?;
	crate::cli::srs::set_domain_secret(document, domain, secret, None)?;
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
	// Whatever was set for the domain goes with it, so nothing in the file
	// names a domain the server no longer hosts.
	own_key::drop_entry(document, domain)?;
	role::forget(document, domain)?;
	if !state::is_enabled(config, domain) {
		state::set_enabled(config, document, domain, true)?;
	}
	for map in ["domain_quotas", "domain_submission_limits"] {
		if let Some(key) = document.map_key(map, |key| key.eq_ignore_ascii_case(domain.trim())) {
			document.remove_map_entry(map, &key)?;
		}
	}
	document.remove_elements("srs_domain", "name", &domain.trim().to_ascii_lowercase())?;
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
	own_key::drop_entry(document, alias)?;
	Ok(())
}

#[cfg(test)]
mod tests;

pub mod blockers;
pub(super) use blockers::removal_blockers;

pub mod writers;
