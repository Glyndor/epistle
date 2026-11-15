//! `epistle domain`: list, show, add and remove the hosted domains; switch
//! them on and off, give them a role, and add or remove domain aliases.
//!
//! Every change is written to `<data_dir>/domains.toml` through
//! [`crate::domain::state::edit`], the layer the `/api/v1/domains` routes
//! write through too, and the running server reloads the file within
//! seconds: nothing restarts `mail`. Role and per-domain limits are
//! committed together without editing the configuration file.
//!
//! `domain add` prints the DNS records the operator now needs to publish,
//! the `dns-records` output scoped to the new domain. `domain remove` refuses
//! while any account, alias, masked address or domain alias still uses the
//! domain, and lists the offenders so the operator knows what to clean up
//! first.

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use super::style;

pub(in crate::cli) mod own_key;
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
	/// Add a domain and print the DNS records the operator now needs to
	/// publish. With `[dkim]` configured the domain gets a DKIM key
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
	/// Stop hosting a domain.
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
	/// Add or remove a domain alias.
	Alias(DomainAliasArgs),
	/// Copy the domain lists of the configuration file into the state file.
	///
	/// Replaces the hosted domains, roles, switches and domain aliases of
	/// `<data_dir>/domains.toml` with what `domains`, `domain_aliases` and
	/// the role lists of the configuration file declare. A domain that would
	/// go is refused while something still uses it.
	Import {
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Set the role, storage quota or submission rate of one domain.
	///
	/// The quota and rate replace the per-domain overrides from the configuration.
	/// A flag that is left out keeps its value; `--no-quota` and
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

#[cfg(test)]
mod tests;

pub mod writers;
