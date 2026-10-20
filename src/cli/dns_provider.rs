//! DNS provider administration: the `[dns]` section.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;

use super::resource;
use super::stack::StackAction;
use crate::config::Config;

#[path = "dns_provider_check.rs"]
mod check;
#[path = "dns_lockdown.rs"]
mod lockdown_handler;
#[path = "dns_provider_probe.rs"]
mod probe;
#[path = "dns_provider_secret.rs"]
mod secret;
#[path = "dns_provider_set.rs"]
mod set;
#[path = "dns_provider_show.rs"]
mod show;

#[cfg(test)]
#[path = "dns_lockdown_tests.rs"]
mod lockdown_tests;
#[cfg(test)]
#[path = "dns_lockdown_tests_cuts.rs"]
mod lockdown_tests_cuts;
#[cfg(test)]
#[path = "dns_provider_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "dns_provider_tests_set.rs"]
mod tests_set;

pub use set::ProviderArgs;

/// DNS administration areas.
#[derive(Debug, Subcommand)]
pub enum DnsCli {
	/// Manage the DNS provider used for record automation.
	Provider {
		/// Provider action.
		#[command(subcommand)]
		action: ProviderCli,
	},
	/// Lock the zone against mail spoofing.
	Lockdown(lockdown_handler::LockdownArgs),
}

/// Provider actions.
#[derive(Debug, Subcommand)]
pub enum ProviderCli {
	/// Report credential capabilities without changing records or settings.
	Check {
		/// Print the same findings as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Show the configured provider. Credentials are never printed.
	Show {
		/// Print the provider settings as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Choose the provider and its zone and credential sources.
	Set {
		/// Provider id, for example cloudflare, route53 or manual.
		provider: String,
		/// The provider settings.
		#[command(flatten)]
		args: Box<ProviderArgs>,
	},
	/// Remove the provider and return to manual DNS.
	Unset,
	/// List the zone's records through the provider (read only).
	Test,
}

pub(super) fn run(path: &Path, action: DnsCli, dry_run: bool, json: bool) -> ExitCode {
	match action {
		DnsCli::Lockdown(args) => lockdown_handler::run(path, args, dry_run),
		action => resource::exit_resource(execute_with(
			path,
			action,
			dry_run,
			json,
			&mut std::io::stdout().lock(),
			&mut super::style::stderr(),
			super::stack::run,
		)),
	}
}

fn execute_with(
	path: &Path,
	action: DnsCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let DnsCli::Provider { action } = action else {
		return Err("dns lockdown runs through its own path; this should not be reached".into());
	};
	let (change, verb, fields): (resource::Change, _, _) = match action {
		ProviderCli::Check { json: leaf } => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(check::config_error(&error)))?;
			check::run(&config, leaf || json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		ProviderCli::Show { json: leaf } => {
			show::run(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		ProviderCli::Test => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			if json {
				let mut printed = Vec::new();
				let code = probe::run(&config, &mut printed, status)?;
				super::json_out::passed(out, "provider test", &printed)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
				return Ok(code);
			}
			return probe::run(&config, out, status);
		}
		ProviderCli::Set { provider, args } => {
			if args.store_token {
				return secret::run(
					path,
					(&provider, &args),
					dry_run,
					json,
					out,
					status,
					restart,
				);
			}
			let fields = set::fields(&provider, &args)?;
			let change: resource::Change = Box::new(move |document, _| {
				document
					.set_table_fields(&["dns"], &fields)
					.map_err(resource::ResourceError::Failure)
			});
			(
				change,
				"provider set",
				serde_json::json!({ "provider": provider }),
			)
		}
		ProviderCli::Unset => {
			let change: resource::Change = Box::new(|document, _| {
				document
					.remove_table(&["dns"])
					.map(|_| ())
					.map_err(resource::ResourceError::Failure)
			});
			(change, "provider unset", serde_json::json!({}))
		}
	};
	let edit = resource::Edit {
		label: "dns provider",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}

#[cfg(all(test, unix))]
#[path = "dns_provider_secret_tests.rs"]
mod tests_secret;
